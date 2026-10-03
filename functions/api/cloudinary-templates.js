import { parse as parseYaml } from 'yaml';
import { jsonResponse, respondWithMappedError } from '../lib/api-errors';
import { getAccessContext } from '../lib/access-auth';
import { getFileFromRepo, listFiles } from '../lib/proxy-github-app';

const GITHUB_API_BASE = 'https://api.github.com';

const sanitizeDir = (value, fallback = 'src/img-template') => {
  const dir = String(value || fallback).trim().replace(/^\/+|\/+$/g, '');
  if (!dir || dir.includes('..')) return fallback;
  return dir;
};

const parseFrontmatter = (text) => {
  const input = String(text || '');
  const m = input.match(/^---\s*\n([\s\S]*?)\n---\s*\n?/);
  if (!m) {
    return { attrs: {}, body: input };
  }
  const attrs = parseYaml(m[1]) || {};
  const body = input.slice(m[0].length);
  return { attrs, body };
};

const decodeBase64Utf8 = (b64) => {
  const normalized = String(b64 || '').replace(/\s/g, '');
  const bytes = Uint8Array.from(atob(normalized), (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
};

const toTemplate = (path, text) => {
  const { attrs } = parseFrontmatter(text);
  const title = attrs?.title || path.split('/').pop();
  return {
    path,
    title: String(title || ''),
    no: String(attrs?.no || ''),
    html: String(attrs?.html || ''),
    srcsetWidths: String(attrs?.srcsetWidths || attrs?.srcset_widths || ''),
    srcWidth: attrs?.srcWidth ?? attrs?.src_width ?? null,
    transform: String(attrs?.transform || ''),
    raw: attrs,
  };
};

const normalizeTemplateSortKey = (t) => {
  const n = Number(t.no);
  return Number.isFinite(n) ? n : Number.MAX_SAFE_INTEGER;
};

const githubList = async ({ token, owner, repo, branch, dir }) => {
  const url = new URL(`${GITHUB_API_BASE}/repos/${owner}/${repo}/contents/${dir}`);
  if (branch) url.searchParams.set('ref', branch);
  const res = await fetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github.v3+json',
      'User-Agent': 'pages-cms-cloudinary/1.0',
    },
  });
  if (!res.ok) throw new Error(`GitHub list failed: ${res.status}`);
  const data = await res.json();
  return Array.isArray(data) ? data : [];
};

const githubGetRaw = async ({ token, owner, repo, branch, path }) => {
  const url = new URL(`${GITHUB_API_BASE}/repos/${owner}/${repo}/contents/${path}`);
  if (branch) url.searchParams.set('ref', branch);
  const res = await fetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github.v3.raw',
      'User-Agent': 'pages-cms-cloudinary/1.0',
    },
  });
  if (!res.ok) throw new Error(`GitHub get failed: ${res.status}`);
  return res.text();
};

const gitlabConfig = (env) => ({
  apiBase: (env.GITLAB_API_BASE || 'https://gitlab.com/api/v4').replace(/\/$/, ''),
});

const projectPath = (owner, repo) => encodeURIComponent(`${owner}/${repo}`);

const gitlabList = async ({ env, token, owner, repo, branch, dir }) => {
  const { apiBase } = gitlabConfig(env);
  const url = new URL(`${apiBase}/projects/${projectPath(owner, repo)}/repository/tree`);
  url.searchParams.set('path', dir);
  url.searchParams.set('ref', branch || 'HEAD');
  url.searchParams.set('per_page', '100');
  const res = await fetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${token}`,
      'User-Agent': 'pages-cms-cloudinary/1.0',
    },
  });
  if (!res.ok) throw new Error(`GitLab list failed: ${res.status}`);
  const data = await res.json();
  return Array.isArray(data) ? data : [];
};

const gitlabGetRaw = async ({ env, token, owner, repo, branch, path }) => {
  const { apiBase } = gitlabConfig(env);
  const url = new URL(`${apiBase}/projects/${projectPath(owner, repo)}/repository/files/${encodeURIComponent(path)}`);
  url.searchParams.set('ref', branch || 'HEAD');
  const res = await fetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${token}`,
      'User-Agent': 'pages-cms-cloudinary/1.0',
    },
  });
  if (!res.ok) throw new Error(`GitLab get failed: ${res.status}`);
  const data = await res.json();
  return decodeBase64Utf8(data?.content || '');
};

const requireToken = (request) => {
  const auth = request.headers.get('authorization') || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) throw new Error('Missing bearer token');
  return m[1];
};

export async function onRequestGet({ request, env }) {
  try {
    const url = new URL(request.url);
    const provider = String(url.searchParams.get('provider') || '').trim();
    const owner = String(url.searchParams.get('owner') || '').trim();
    const repo = String(url.searchParams.get('repo') || '').trim();
    const branch = String(url.searchParams.get('branch') || '').trim();
    const dir = sanitizeDir(url.searchParams.get('dir') || env.CLOUDINARY_TEMPLATE_DIR || 'src/img-template');

    if (!provider || !owner || !repo) {
      return jsonResponse({ error: 'BAD_REQUEST', message: 'provider, owner and repo are required' }, 400);
    }

    let paths = [];
    const templates = [];

    if (provider === 'proxy_github_app') {
      const access = await getAccessContext(request, env);
      if (!access.accessEnabled) {
        return jsonResponse({ error: 'FORBIDDEN', message: 'Cloudflare Access mode is disabled' }, 403);
      }

      const listing = await listFiles({
        env,
        query: { owner, repo, branch, path: dir },
      });
      paths = (Array.isArray(listing) ? listing : [])
        .filter((item) => item?.type === 'blob' && /\.md$/i.test(item.path || ''))
        .map((item) => item.path);
      for (const path of paths) {
        // eslint-disable-next-line no-await-in-loop
        const raw = await getFileFromRepo({ env, query: { owner, repo, branch, path, raw: true } });
        templates.push(toTemplate(path, raw));
      }
    } else if (provider === 'github') {
      const token = requireToken(request);
      const listing = await githubList({ token, owner, repo, branch, dir });
      paths = (Array.isArray(listing) ? listing : [])
        .filter((item) => item?.type === 'file' && /\.md$/i.test(item.path || ''))
        .map((item) => item.path);
      for (const path of paths) {
        // eslint-disable-next-line no-await-in-loop
        const raw = await githubGetRaw({ token, owner, repo, branch, path });
        templates.push(toTemplate(path, raw));
      }
    } else if (provider === 'gitlab') {
      const token = requireToken(request);
      const listing = await gitlabList({ env, token, owner, repo, branch, dir });
      paths = (Array.isArray(listing) ? listing : [])
        .filter((item) => item?.type === 'blob' && /\.md$/i.test(item.path || ''))
        .map((item) => item.path);
      for (const path of paths) {
        // eslint-disable-next-line no-await-in-loop
        const raw = await gitlabGetRaw({ env, token, owner, repo, branch, path });
        templates.push(toTemplate(path, raw));
      }
    } else {
      return jsonResponse({ error: 'BAD_REQUEST', message: `Unsupported provider: ${provider}` }, 400);
    }

    templates.sort((a, b) => {
      const noCmp = normalizeTemplateSortKey(a) - normalizeTemplateSortKey(b);
      if (noCmp !== 0) return noCmp;
      return a.title.localeCompare(b.title);
    });

    return jsonResponse({
      dir,
      count: templates.length,
      templates,
    });
  } catch (error) {
    return respondWithMappedError(error);
  }
}
