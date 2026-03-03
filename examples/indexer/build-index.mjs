// Example index builder for Pages CMS content repositories (ESM).
// Copy this file into your content repo (e.g. scripts/build-index.mjs) and
// run via GitHub Actions or manually: `node scripts/build-index.mjs`.
// Depends on: yaml, @ltd/j-toml (install with `npm i yaml @ltd/j-toml`).

import fs from 'fs/promises';
import path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import YAML from 'yaml';
import * as TOML from '@ltd/j-toml';

const exec = promisify(execFile);
const REPO_ROOT = process.cwd();
const INDEX_DIR = path.join(REPO_ROOT, 'indexes');
const DEFAULT_SPLIT_MB = 2;
const PARENTS_COUNT = 30;
const SCHEMA_VERSION = 1;

const codeExtensions = ['yaml', 'yml', 'javascript', 'js', 'jsx', 'typescript', 'ts', 'tsx', 'json', 'html', 'htm', 'markdown', 'md', 'mdx'];

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

async function main() {
  await fs.mkdir(INDEX_DIR, { recursive: true });
  const pagesPath = path.join(REPO_ROOT, '.pages.yml');
  if (!(await fileExists(pagesPath))) {
    console.error('No .pages.yml found at repo root. Skipping index generation.');
    return;
  }

  const rawConfig = await fs.readFile(pagesPath, 'utf8');
  const config = YAML.parse(rawConfig, { strict: false }) || {};
  const splitLimitMb = config.indexSplitSize ?? DEFAULT_SPLIT_MB;
  const collections = (config.content || []).filter((item) => item?.type === 'collection');
  if (collections.length === 0) {
    console.warn('No collections defined in .pages.yml. Nothing to index.');
    return;
  }

  const contentSha = (await exec('git', ['rev-parse', 'HEAD'], { cwd: REPO_ROOT })).stdout.trim();
  const contentParents = (await exec('git', ['rev-list', `--max-count=${PARENTS_COUNT}`, 'HEAD'], { cwd: REPO_ROOT })).stdout.split('\n').filter(Boolean);
  const generatedAt = new Date().toISOString();

  for (const rawItem of collections) {
    const item = normalizeCollection(rawItem);
    await buildCollectionIndex({
      collection: item,
      contentSha,
      contentParents,
      generatedAt,
      splitLimitMb,
    });
  }
}

function normalizeCollection(item) {
  const copy = JSON.parse(JSON.stringify(item || {}));
  if (copy.path) copy.path = copy.path.replace(/^\/|\/$/g, '');

  if (!copy.extension) {
    if (copy.filename) {
      const parts = copy.filename.split('.');
      copy.extension = parts.length > 1 ? parts.pop() : 'md';
    } else {
      copy.extension = 'md';
    }
  }

  if (!copy.format) {
    if (copy.fields?.length > 0) {
      switch (copy.extension) {
        case 'json':
          copy.format = 'json';
          break;
        case 'toml':
          copy.format = 'toml';
          break;
        case 'yaml':
        case 'yml':
          copy.format = 'yaml';
          break;
        default:
          copy.format = 'yaml-frontmatter';
      }
    } else if (codeExtensions.includes(copy.extension)) {
      copy.format = 'code';
    } else if (copy.extension === 'csv') {
      copy.format = 'datagrid';
    } else {
      copy.format = 'yaml-frontmatter';
    }
  }
  return copy;
}

function determineFields(collection) {
  if (collection.indexAllFrontmatter) return null; // null => take all fields
  const set = new Set();
  if (Array.isArray(collection.indexFields)) {
    collection.indexFields.forEach((f) => set.add(f));
  }
  if (Array.isArray(collection.fields)) {
    collection.fields.forEach((f) => set.add(f.name));
  }
  if (collection.view) {
    if (collection.view.primary) set.add(collection.view.primary);
    if (Array.isArray(collection.view.fields)) collection.view.fields.forEach((f) => set.add(f));
    if (Array.isArray(collection.view.sort)) collection.view.sort.forEach((f) => set.add(f));
    if (collection.view.default?.sort) set.add(collection.view.default.sort);
  }
  return Array.from(set);
}

function getDateFromFilename(filename) {
  const pattern = /^(\d{4})-(\d{2})-(\d{2})-/;
  const match = filename.match(pattern);
  if (match) {
    const [, year, month, day] = match;
    const date = new Date(`${year}-${month}-${day}`);
    if (!Number.isNaN(date.getTime())) {
      return { year, month, day, string: `${year}-${month}-${day}` };
    }
  }
  return undefined;
}

async function buildCollectionIndex({ collection, contentSha, contentParents, generatedAt, splitLimitMb }) {
  const indexName = `${collection.name || path.basename(collection.path) || 'collection'}`;
  const dirPath = path.join(REPO_ROOT, collection.path || '');
  if (!(await dirExists(dirPath))) {
    console.warn(`[skip] ${indexName}: path not found (${dirPath})`);
    return;
  }

  const fieldList = determineFields(collection);
  const files = await walkFiles(dirPath);
  const items = [];

  for (const fullPath of files) {
    if (collection.extension && !fullPath.endsWith(`.${collection.extension}`)) continue;

    const text = await fs.readFile(fullPath, 'utf8');
    let frontmatter = {};
    if (collection.format && collection.format.includes('frontmatter')) {
      try {
        const parsed = parseFrontmatter(text, collection.format, collection.delimiters);
        frontmatter = { ...parsed };
        delete frontmatter.body;
      } catch (err) {
        console.warn(`[warn] frontmatter parse failed for ${fullPath}:`, err.message);
        frontmatter = {};
      }
    }

    let fieldsSubset;
    if (fieldList === null) {
      fieldsSubset = frontmatter;
    } else {
      fieldsSubset = {};
      fieldList.forEach((key) => {
        if (frontmatter && Object.prototype.hasOwnProperty.call(frontmatter, key)) {
          fieldsSubset[key] = frontmatter[key];
        }
      });
    }

    const filename = path.basename(fullPath);
    const relPath = path.posix.join(collection.path || '', path.relative(dirPath, fullPath).replace(/\\/g, '/'));
    const dateFromFilename = getDateFromFilename(filename);
    if (dateFromFilename && fieldsSubset.date == null) {
      fieldsSubset.date_from_filename = dateFromFilename.string;
    }

    const stat = await fs.stat(fullPath);
    const sha = (await exec('git', ['hash-object', fullPath], { cwd: REPO_ROOT })).stdout.trim();
    let updatedAt = null;
    try {
      updatedAt = (await exec('git', ['log', '-1', '--format=%cI', '--', fullPath], { cwd: REPO_ROOT })).stdout.trim() || null;
    } catch (_) {
      updatedAt = null;
    }

    items.push({
      path: relPath,
      filename,
      sha,
      size: stat.size,
      updated_at: updatedAt,
      ...fieldsSubset,
    });
  }

  const sorted = sortItems(items, collection);
  await writeIndexFiles({
    indexName,
    items: sorted,
    meta: {
      collection: indexName,
      content_sha: contentSha,
      content_parents: contentParents,
      generated_at: generatedAt,
      schema_version: SCHEMA_VERSION,
    },
    splitLimitMb,
  });
  console.log(`[ok] ${indexName}: ${items.length} items`);
}

function sortItems(items, collection) {
  if (!items.length) return items;
  const primarySort = collection.view?.default?.sort || collection.view?.sort?.[0] || 'date';
  const order = collection.view?.default?.order || 'desc';
  return [...items].sort((a, b) => {
    const valA = a[primarySort];
    const valB = b[primarySort];
    if (valA == null && valB == null) return 0;
    if (valA == null) return 1;
    if (valB == null) return -1;
    if (valA < valB) return order === 'desc' ? 1 : -1;
    if (valA > valB) return order === 'desc' ? -1 : 1;
    return 0;
  });
}

async function writeIndexFiles({ indexName, items, meta, splitLimitMb }) {
  const limitBytes = Math.max(1, splitLimitMb) * 1024 * 1024;
  const base = { meta, items };
  const json = JSON.stringify(base, null, 2);
  if (Buffer.byteLength(json, 'utf8') <= limitBytes) {
    const outPath = path.join(INDEX_DIR, `${indexName}.json`);
    await fs.writeFile(outPath, json + '\n');
    return;
  }
  let current = [];
  let part = 1;
  for (const item of items) {
    current.push(item);
    const candidate = JSON.stringify({ meta: { ...meta, page: part }, items: current }, null, 2);
    if (Buffer.byteLength(candidate, 'utf8') > limitBytes) {
      current.pop();
      await flushPart(indexName, part, meta, current);
      part += 1;
      current = [item];
    }
  }
  if (current.length) {
    await flushPart(indexName, part, meta, current);
  }
}

async function flushPart(indexName, part, meta, items) {
  const payload = { meta: { ...meta, page: part }, items };
  const outPath = path.join(INDEX_DIR, `${indexName}.part${part}.json`);
  await fs.writeFile(outPath, JSON.stringify(payload, null, 2) + '\n');
}

async function walkFiles(dir) {
  const acc = [];
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      acc.push(...await walkFiles(full));
    } else if (e.isFile()) {
      acc.push(full);
    }
  }
  return acc;
}

function parseFrontmatter(content = '', format = 'yaml-frontmatter', delimitersOpt) {
  const delimiters = setDelimiter(delimitersOpt, format);
  const startDelimiter = escapeRegex(delimiters[0]);
  const endDelimiter = escapeRegex(delimiters[1]);
  const frontmatterRegex = new RegExp(`^(${startDelimiter}(?:\\n|\\r)?([\\s\\S]+?)(?:\\n|\\r)?${endDelimiter})\\n*([\\s\\S]*)`);
  const match = frontmatterRegex.exec(content);
  if (!match) return { body: content };
  const fm = deserialize(match[2], format.split('-')[0]);
  return { ...fm, body: (match[3] || '').replace(/^\\n/, '') };
}

function deserialize(content = '', format = 'yaml') {
  if (!content.trim()) return {};
  switch (format) {
    case 'yaml':
      return YAML.parse(content, { strict: false, uniqueKeys: false });
    case 'json':
      return JSON.parse(content);
    case 'toml':
      return JSON.parse(JSON.stringify(TOML.parse(content, 1.0, '\n', false)));
    default:
      return {};
  }
}

function setDelimiter(delimiters, format) {
  if (delimiters === undefined) {
    switch (format) {
      case 'toml-frontmatter':
        delimiters = '+++';
        break;
      case 'json-frontmatter':
      case 'yaml-frontmatter':
      default:
        delimiters = '---';
    }
  }
  if (typeof delimiters === 'string') {
    delimiters = [delimiters, delimiters];
  }
  return delimiters;
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&');
}

async function fileExists(p) {
  try {
    await fs.access(p);
    return true;
  } catch (_) {
    return false;
  }
}

async function dirExists(p) {
  try {
    const stat = await fs.stat(p);
    return stat.isDirectory();
  } catch (_) {
    return false;
  }
}
