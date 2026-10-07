// Basic public index builder for Pages CMS content repositories (ESM).
// Copy into your content repo as scripts/build-public-index.mjs and run:
//   node scripts/build-public-index.mjs
// Depends on: yaml, glob (npm i yaml glob)

import fs from 'fs/promises';
import path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import YAML from 'yaml';
import { glob } from 'glob';

const exec = promisify(execFile);
const REPO_ROOT = process.cwd();
const DEFAULT_OUT_DIR = 'indexes-public';
const DEFAULT_PAGE_SIZE = 20;
const ZERO_SHA = '0000000000000000000000000000000000000000';
const FORCE_PUBLIC_INDEX_REBUILD = isTruthyEnv(process.env.FORCE_PUBLIC_INDEX_REBUILD);

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

async function main() {
  const pagesPath = path.join(REPO_ROOT, '.pages.yml');
  if (!(await fileExists(pagesPath))) {
    console.error('No .pages.yml found at repo root. Skipping public index generation.');
    return;
  }

  const rawConfig = await fs.readFile(pagesPath, 'utf8');
  const config = YAML.parse(rawConfig, { strict: false }) || {};
  const publicCfg = config.publicIndex || {};

  const outDir = path.join(REPO_ROOT, String(publicCfg.outputDir || DEFAULT_OUT_DIR));
  const pageSize = Number(publicCfg.pageSize || DEFAULT_PAGE_SIZE);
  const onlyPublished = publicCfg.onlyPublished !== false;
  const publishedField = String(publicCfg.publishedField || 'published');
  const sortField = String(publicCfg.sortField || 'date');
  const sortOrder = String(publicCfg.sortOrder || 'desc').toLowerCase() === 'asc' ? 'asc' : 'desc';

  await fs.mkdir(outDir, { recursive: true });

  const collections = (config.content || [])
    .filter((item) => item?.type === 'collection')
    .map(normalizeCollection)
    .filter((col) => col.path);

  const include = new Set((publicCfg.includeCollections || []).map((x) => String(x || '').trim()).filter(Boolean));
  const targetCollections = include.size > 0
    ? collections.filter((c) => include.has(c.name) || include.has(c.path))
    : collections;

  if (targetCollections.length === 0) {
    console.warn('No target collections for public index.');
    return;
  }

  let { rebuildAll, targets } = await determineTargets(targetCollections);
  if (FORCE_PUBLIC_INDEX_REBUILD) {
    rebuildAll = true;
    targets = new Set();
    console.log('Rebuild mode forced by FORCE_PUBLIC_INDEX_REBUILD=1');
  } else if (!rebuildAll) {
    const missingTargets = await detectMissingTargets(targetCollections, outDir);
    for (const t of missingTargets) targets.add(t);
    if (missingTargets.size > 0)
      console.log(`Missing outputs detected -> add targets: [${Array.from(missingTargets).join(', ')}]`);
  }

  if (!rebuildAll && targets.size === 0) {
    console.log('No affected collections detected. Skipping public index generation.');
    return;
  }

  for (const col of targetCollections) {
    if (!rebuildAll && !targets.has(col.path)) {
      console.log(`[skip] ${col.name || col.path}: no changes in this collection`);
      continue;
    }

    const items = await readCollectionItems(col);
    const normalized = items
      .map((it) => normalizePublicItem(it, col))
      .filter((it) => it.id !== '');

    const filtered = onlyPublished
      ? normalized.filter((it) => toBoolean(it[publishedField], true))
      : normalized;

    const sorted = sortItems(filtered, sortField, sortOrder);
    await writeCollectionOutputs({ outDir, collection: col, items: sorted, pageSize, sortField, sortOrder });
  }
}

function normalizeCollection(item) {
  const copy = JSON.parse(JSON.stringify(item || {}));
  if (copy.path) copy.path = String(copy.path).replace(/^\/|\/$/g, '');
  return copy;
}

async function readCollectionItems(col) {
  const root = path.join(REPO_ROOT, col.path);
  if (!(await dirExists(root))) return [];

  const ext = (col.extension || 'md').replace(/^\./, '');
  const files = await glob(`**/*.${ext}`, { cwd: root, nodir: true });
  const out = [];

  for (const rel of files) {
    const full = path.join(root, rel);
    const raw = await fs.readFile(full, 'utf8');
    const parsed = parseFrontmatterLoose(raw);
    const relPath = path.posix.join(col.path, rel.replace(/\\/g, '/'));
    out.push({
      path: relPath,
      filename: path.basename(rel),
      frontmatter: parsed.frontmatter,
      body: parsed.body,
    });
  }
  return out;
}

function normalizePublicItem(src, col) {
  const fm = src.frontmatter || {};
  const idFromFilename = String(src.filename || '').replace(/\.[^.]+$/, '');
  const id = String(fm.id || idFromFilename || '').trim();
  const title = String(fm.title || fm.name || id).trim();
  const date = String(fm.date || fm.published_at || '').trim();
  const excerpt = String(fm.excerpt || '').trim() || normalizeExcerpt(src.body, 180);
  const lang = String(col.name || '').endsWith('-ja') ? 'ja' : (String(col.name || '').endsWith('-en') ? 'en' : '');

  return {
    id,
    title,
    date,
    excerpt,
    path: src.path,
    filename: src.filename,
    lang,
    ...fm,
  };
}

function normalizeExcerpt(body, limit = 180) {
  const text = String(body || '')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<[^>]*>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return text.length <= limit ? text : text.slice(0, limit);
}

function sortItems(items, field, order) {
  const dir = order === 'asc' ? 1 : -1;
  return [...items].sort((a, b) => {
    const av = a[field];
    const bv = b[field];
    if (av == null && bv == null) return 0;
    if (av == null) return 1;
    if (bv == null) return -1;
    if (String(av) < String(bv)) return -1 * dir;
    if (String(av) > String(bv)) return 1 * dir;
    return 0;
  });
}

async function writeCollectionOutputs({ outDir, collection, items, pageSize, sortField, sortOrder }) {
  const name = String(collection.name || path.basename(collection.path) || 'collection');
  const listDir = path.join(outDir, 'list', name);

  await removePathRecursive(path.join(outDir, `manifest.${name}.json`));
  await removePathRecursive(path.join(outDir, `lookup.${name}.json`));
  await removePathRecursive(listDir);

  await fs.mkdir(listDir, { recursive: true });

  const lookup = {};
  for (const it of items) {
    lookup[it.id] = {
      path: it.path,
      title: it.title,
      date: it.date,
      excerpt: it.excerpt,
      lang: it.lang,
    };
  }

  const pages = chunk(items, Math.max(1, Number(pageSize) || DEFAULT_PAGE_SIZE));
  const routes = [];
  for (let i = 0; i < pages.length; i += 1) {
    const page = i + 1;
    const rel = path.posix.join('list', name, `page-${page}.json`);
    const out = path.join(outDir, rel);
    await fs.mkdir(path.dirname(out), { recursive: true });

    await fs.writeFile(
      out,
      JSON.stringify(
        {
          schema_version: 1,
          collection: name,
          page,
          page_size: pageSize,
          total_items: items.length,
          total_pages: pages.length,
          items: pages[i],
        },
        null,
        2
      ) + '\n'
    );

    routes.push({ page, file: rel, total_items: items.length, total_pages: pages.length });
  }

  await fs.writeFile(
    path.join(outDir, `lookup.${name}.json`),
    JSON.stringify({ schema_version: 1, collection: name, lookup }, null, 2) + '\n'
  );

  await fs.writeFile(
    path.join(outDir, `manifest.${name}.json`),
    JSON.stringify(
      {
        schema_version: 1,
        collection: name,
        generated_at: new Date().toISOString(),
        sort_field: sortField,
        sort_order: sortOrder,
        page_size: pageSize,
        total_items: items.length,
        routes,
      },
      null,
      2
    ) + '\n'
  );

  console.log(`[ok] ${name}: ${items.length} items`);
}

function chunk(list, size) {
  const out = [];
  for (let i = 0; i < list.length; i += size) {
    out.push(list.slice(i, i + size));
  }
  return out;
}

function parseFrontmatterLoose(raw) {
  const text = String(raw || '');
  if (!text.startsWith('---')) return { frontmatter: {}, body: text };
  const m = text.match(/^---\s*\n([\s\S]*?)\n---\s*\n?([\s\S]*)$/);
  if (!m) return { frontmatter: {}, body: text };
  try {
    return {
      frontmatter: YAML.parse(m[1], { strict: false }) || {},
      body: m[2] || '',
    };
  } catch (err) {
    console.warn(`[warn] frontmatter parse failed: ${err?.message || err}`);
    return { frontmatter: {}, body: m[2] || '' };
  }
}

async function determineTargets(collections) {
  const result = { rebuildAll: false, targets: new Set() };

  const payload = await readPushPayload();
  const before = payload?.before;
  const after = payload?.after;

  if (!before || !after || before === ZERO_SHA) {
    result.rebuildAll = true;
    return result;
  }

  const changes = await collectChangedPaths(before, after);
  if (!changes) {
    result.rebuildAll = true;
    return result;
  }

  if (changes.has('.pages.yml')) {
    result.rebuildAll = true;
    return result;
  }

  for (const change of changes) {
    for (const col of collections) {
      const colPath = col.path || '';
      if (!colPath) continue;
      if (change === colPath || change.startsWith(`${colPath}/`)) {
        result.targets.add(colPath);
      }
    }
  }

  return result;
}

async function detectMissingTargets(collections, outDir) {
  const missing = new Set();
  for (const col of collections) {
    const name = String(col.name || path.basename(col.path) || 'collection');
    const required = [
      path.join(outDir, `manifest.${name}.json`),
      path.join(outDir, `lookup.${name}.json`),
    ];
    if (!(await allExist(required))) missing.add(col.path);
  }
  return missing;
}

async function readPushPayload() {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath) return null;
  try {
    const raw = await fs.readFile(eventPath, 'utf8');
    const json = JSON.parse(raw);
    if (json?.before && json?.after) return { before: json.before, after: json.after };
  } catch (_) {
    return null;
  }
  return null;
}

async function collectChangedPaths(before, after) {
  const changes = new Set();
  const runDiff = () => exec('git', ['diff', '--name-status', '-z', `${before}..${after}`], {
    cwd: REPO_ROOT,
    encoding: 'buffer',
    maxBuffer: 10 * 1024 * 1024,
  });

  const parse = (stdout) => {
    const tokens = stdout.toString('utf8').split('\0').filter(Boolean);
    for (let i = 0; i < tokens.length;) {
      const status = tokens[i];
      const code = status?.[0];
      const pathA = tokens[i + 1];
      if (!status || !pathA) break;
      changes.add(pathA);
      if (code === 'R' || code === 'C') {
        const pathB = tokens[i + 2];
        if (pathB) changes.add(pathB);
        i += 3;
      } else {
        i += 2;
      }
    }
  };

  try {
    const { stdout } = await runDiff();
    parse(stdout);
  } catch (err) {
    console.warn(`collectChangedPaths failed (${err?.message || err}); retrying with fetch --deepen=50`);
    try {
      await exec('git', ['fetch', '--deepen=50', 'origin', 'main'], { cwd: REPO_ROOT });
      const { stdout } = await runDiff();
      parse(stdout);
    } catch {
      return null;
    }
  }

  return changes;
}

async function allExist(paths) {
  for (const p of paths) {
    if (!(await fileExists(p))) return false;
  }
  return true;
}

async function removePathRecursive(targetPath) {
  try {
    await fs.rm(targetPath, { recursive: true, force: true });
  } catch {
    // ignore
  }
}

async function fileExists(p) {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

async function dirExists(p) {
  try {
    const st = await fs.stat(p);
    return st.isDirectory();
  } catch {
    return false;
  }
}

function toBoolean(v, fallback = false) {
  if (v === undefined || v === null || v === '') return fallback;
  const s = String(v).trim().toLowerCase();
  return s === '1' || s === 'true' || s === 'yes' || s === 'on';
}

function isTruthyEnv(v) {
  if (v === undefined || v === null) return false;
  const s = String(v).trim().toLowerCase();
  return s === '1' || s === 'true' || s === 'yes' || s === 'on';
}
