/**
 * Lightweight index fetcher for content repositories.
 * Tries to read indexes/<collection>.json (or part files) and returns parsed data.
 * Falls back to null if no index is available so callers can revert to legacy behavior.
 */

import github from '@/services/github';

const memoryCache = new Map(); // key: owner/repo/branch/collection

const RESERVED_KEYS = new Set(['path', 'filename', 'sha', 'size', 'updated_at', 'collection']);

const cacheKey = (owner, repo, branch, collection) => `${owner}/${repo}/${branch}/${collection}`;

const parseIndex = (raw, sourcePath) => {
  const cleaned = raw && raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
  const parsed = JSON.parse(cleaned);
  if (!parsed || !parsed.items || !parsed.meta) {
    throw new Error(`Invalid index format (${sourcePath})`);
  }
  return parsed;
};

const safeParse = (raw, sourcePath) => {
  if (!raw) return null;
  try {
    return parseIndex(raw, sourcePath);
  } catch (e) {
    console.warn(`Failed to parse index ${sourcePath}`, e);
    return null;
  }
};

const decodeContent = (res) => {
  if (!res) return null;
  if (typeof res === 'string') return res;
  const b64 = res.content;
  if (typeof b64 !== 'string') return null;

  // Decode base64 to UTF-8 safely (browser or Node)
  try {
    if (typeof window !== 'undefined' && typeof window.atob === 'function') {
      const binary = window.atob(b64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return new TextDecoder('utf-8').decode(bytes);
    }
    // Node fallback
    return Buffer.from(b64, 'base64').toString('utf-8');
  } catch (e) {
    console.warn('Failed to decode index content', e);
    return null;
  }
};

const fetchIndexFile = async (owner, repo, branch, path) => {
  // Fetch metadata (non-raw) once; decide best path based on presence of content/download_url.
  const res = await github.getFile(owner, repo, branch, path, false);
  if (!res) return null;

  // If base64 content is present (usually <=1MB), decode and return.
  const decoded = decodeContent(res);
  if (decoded) return decoded;

  // For large files GitHub omits content; fetch via download_url (gzipされるため転送量が小さい)
  if (res.download_url) {
    try {
      const fetchRes = await fetch(res.download_url);
      if (fetchRes.ok) {
        return await fetchRes.text();
      }
    } catch (e) {
      console.warn('Failed fetching download_url', e);
    }
  }

  // Last resort: try raw (not expected to hit normally)
  const raw = await github.getFile(owner, repo, branch, path, true);
  if (typeof raw === 'string' && raw.trim() !== '') {
    return raw;
  }

  return null;
};

const fetchIndex = async (owner, repo, branch, collection) => {
  const key = cacheKey(owner, repo, branch, collection);
  if (memoryCache.has(key)) return memoryCache.get(key);

  // Try single file (preferred)
  const basePath = `indexes/${collection}.json`;
  const baseRaw = await fetchIndexFile(owner, repo, branch, basePath);
  const baseParsed = safeParse(baseRaw, basePath);
  if (baseParsed) {
    memoryCache.set(key, baseParsed);
    return baseParsed;
  }

  // Try split parts
  let part = 1;
  let items = [];
  let meta = null;
  while (true) {
    const partPath = `indexes/${collection}.part${part}.json`;
    const partRaw = await fetchIndexFile(owner, repo, branch, partPath);
    const parsed = safeParse(partRaw, partPath);
    if (!parsed) break;
    if (!meta) meta = parsed.meta;
    items = items.concat(parsed.items || []);
    part += 1;
  }
  if (items.length > 0 && meta) {
    const merged = { meta, items };
    memoryCache.set(key, merged);
    return merged;
  }

  return null; // No index available
};

const toCollectionItems = (indexItems, folderFilter = null) => {
  const files = [];
  const folders = new Set();

  indexItems.forEach((item) => {
    if (folderFilter && !item.path.startsWith(folderFilter)) return;
    const relPath = folderFilter ? item.path.slice(folderFilter.length).replace(/^\//, '') : item.path;
    // Derive immediate child folder for breadcrumb when filtered
    if (folderFilter && relPath.includes('/')) {
      folders.add(relPath.split('/')[0]);
    }
    const fields = {};
    Object.keys(item).forEach((k) => {
      if (!RESERVED_KEYS.has(k)) {
        fields[k] = item[k];
      }
    });
    files.push({
      sha: item.sha,
      filename: item.filename,
      path: item.path,
      size: item.size,
      updated_at: item.updated_at,
      fields,
      type: 'blob',
      // content is intentionally omitted; will be loaded lazily if needed
    });
  });

  return {
    files,
    folders: Array.from(folders).map((name) => ({
      name,
      path: folderFilter ? `${folderFilter}/${name}`.replace(/\\/g, '/') : name,
      type: 'tree',
    })),
  };
};

export default { fetchIndex, toCollectionItems };
