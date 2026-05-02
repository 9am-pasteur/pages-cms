import { getProxyRepoConfig, resolvePathPolicy } from './access-auth';

const textEncoder = new TextEncoder();
const GITHUB_API_BASE = 'https://api.github.com';

const normalizePath = (input = '') => {
  const raw = String(input || '').replace(/\\/g, '/').trim();
  const parts = raw.split('/').filter(Boolean);
  const stack = [];
  for (const part of parts) {
    if (part === '.') continue;
    if (part === '..') {
      stack.pop();
      continue;
    }
    stack.push(part);
  }
  return stack.join('/');
};

const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const globToRegExp = (glob) => {
  let out = '^';
  for (let i = 0; i < glob.length; i += 1) {
    const ch = glob[i];
    if (ch === '*') {
      const next = glob[i + 1];
      if (next === '*') {
        out += '.*';
        i += 1;
      } else {
        out += '[^/]*';
      }
    } else if (ch === '?') {
      out += '.';
    } else {
      out += escapeRegExp(ch);
    }
  }
  out += '$';
  return new RegExp(out);
};

const matchesPattern = (path, pattern) => {
  const normalizedPath = normalizePath(path);
  const normalizedPattern = normalizePath(pattern);
  if (normalizedPattern.endsWith('/**')) {
    const prefix = normalizedPattern.slice(0, -3);
    if (normalizedPath === prefix || normalizedPath.startsWith(`${prefix}/`)) {
      return true;
    }
  }
  return globToRegExp(normalizedPattern).test(normalizedPath);
};

const matchesAnyPattern = (path, patterns) => {
  const normalized = normalizePath(path);
  return patterns.some((pattern) => matchesPattern(normalized, pattern));
};

const isPathAllowedByPolicy = (path, policy) => {
  const normalized = normalizePath(path);
  if (!normalized) return false;
  if (matchesAnyPattern(normalized, policy.denied || [])) return false;
  return matchesAnyPattern(normalized, policy.allowed || []);
};

const ensurePathAllowed = (path, env) => {
  const policy = resolvePathPolicy(env);
  if (!isPathAllowedByPolicy(path, policy)) {
    throw new Error(`Path is not allowed: ${path}`);
  }
  return normalizePath(path);
};

const getRequiredEnv = (env, key) => {
  const value = (env[key] || '').trim();
  if (!value) throw new Error(`Missing env: ${key}`);
  return value;
};

const pemToArrayBuffer = (pem) => {
  const stripped = pem
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
  const raw = atob(stripped);
  const bytes = Uint8Array.from(raw, (ch) => ch.charCodeAt(0));
  return bytes.buffer;
};

const base64url = (inputBytes) =>
  btoa(String.fromCharCode(...inputBytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');

const utf8Base64url = (value) => base64url(textEncoder.encode(value));

const signGithubAppJwt = async (env) => {
  const appId = getRequiredEnv(env, 'GITHUB_APP_ID');
  const privateKeyPem = getRequiredEnv(env, 'GITHUB_APP_PRIVATE_KEY');

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = { iat: now - 60, exp: now + 9 * 60, iss: appId };

  const encodedHeader = utf8Base64url(JSON.stringify(header));
  const encodedPayload = utf8Base64url(JSON.stringify(payload));
  const unsigned = `${encodedHeader}.${encodedPayload}`;

  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(privateKeyPem),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', cryptoKey, textEncoder.encode(unsigned));
  const encodedSignature = base64url(new Uint8Array(signature));
  return `${unsigned}.${encodedSignature}`;
};

const createInstallationToken = async (env) => {
  const jwt = await signGithubAppJwt(env);
  const installationId = getRequiredEnv(env, 'GITHUB_APP_INSTALLATION_ID');

  const res = await fetch(`${GITHUB_API_BASE}/app/installations/${installationId}/access_tokens`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${jwt}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Failed to create installation token: ${res.status} ${text}`);
  }
  const data = await res.json();
  return data.token;
};

const githubRequest = async (token, method, path, body = null, query = null) => {
  const url = new URL(`${GITHUB_API_BASE}${path}`);
  if (query) {
    Object.entries(query).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') {
        url.searchParams.set(key, String(value));
      }
    });
  }

  const res = await fetch(url.toString(), {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub API failed (${method} ${path}): ${res.status} ${text}`);
  }

  if (res.status === 204) return null;
  return res.json();
};

const getFixedRepo = (env) => {
  const repo = getProxyRepoConfig(env);
  if (!repo.owner || !repo.name) {
    throw new Error('Missing proxy repository configuration');
  }
  return repo;
};

const assertRepoMatchesFixed = (query, env) => {
  const fixed = getFixedRepo(env);
  if (query?.owner && query.owner !== fixed.owner) throw new Error('owner mismatch');
  if (query?.repo && query.repo !== fixed.name) throw new Error('repo mismatch');
  return fixed;
};

const mapContentsToEntries = (value) => {
  const list = Array.isArray(value) ? value : [value];
  return list.map((item) => ({
    name: item.name,
    path: item.path,
    type: item.type === 'dir' ? 'tree' : 'blob',
    object: item.type === 'file'
      ? {
          text: item.content ? atob((item.content || '').replace(/\n/g, '')) : undefined,
          oid: item.sha,
        }
      : undefined,
  }));
};

export const getProxyContext = async (env, query = null) => {
  const repo = assertRepoMatchesFixed(query, env);
  const token = await createInstallationToken(env);
  return { repo, token };
};

export const assertAllowedPath = (path, env) => ensurePathAllowed(path, env);

export const listFiles = async ({ env, query }) => {
  const { repo, token } = await getProxyContext(env, query);
  const path = assertAllowedPath(query.path || '', env);
  const ref = query.branch || repo.branch;
  const encodedPath = encodeURIComponent(path).replace(/%2F/g, '/');
  const data = await githubRequest(token, 'GET', `/repos/${repo.owner}/${repo.name}/contents/${encodedPath}`, null, { ref });
  return mapContentsToEntries(data);
};

export const getFileFromRepo = async ({ env, query }) => {
  const { repo, token } = await getProxyContext(env, query);
  const path = assertAllowedPath(query.path || '', env);
  const ref = query.branch || repo.branch;
  const encodedPath = encodeURIComponent(path).replace(/%2F/g, '/');
  const data = await githubRequest(token, 'GET', `/repos/${repo.owner}/${repo.name}/contents/${encodedPath}`, null, { ref });
  if (query.raw === 'true' || query.raw === true) {
    return atob((data.content || '').replace(/\n/g, ''));
  }
  return data;
};

export const getCommitsForPath = async ({ env, query }) => {
  const { repo, token } = await getProxyContext(env, query);
  const path = assertAllowedPath(query.path || '', env);
  const sha = query.branch || repo.branch;
  const data = await githubRequest(token, 'GET', `/repos/${repo.owner}/${repo.name}/commits`, null, { sha, path });
  return data;
};

export const saveFileToRepo = async ({ env, body }) => {
  const { repo, token } = await getProxyContext(env, body);
  const path = assertAllowedPath(body.path || '', env);
  const branch = body.branch || repo.branch;
  const encodedPath = encodeURIComponent(path).replace(/%2F/g, '/');
  const data = await githubRequest(token, 'PUT', `/repos/${repo.owner}/${repo.name}/contents/${encodedPath}`, {
    message: body.sha ? `Update ${path} (via Pages CMS)` : `Create ${path} (via Pages CMS)`,
    content: body.content,
    branch,
    ...(body.sha ? { sha: body.sha } : {}),
  });
  return data;
};

export const deleteFileFromRepo = async ({ env, body }) => {
  const { repo, token } = await getProxyContext(env, body);
  const path = assertAllowedPath(body.path || '', env);
  const branch = body.branch || repo.branch;
  if (!body.sha) {
    throw new Error('sha is required');
  }
  const encodedPath = encodeURIComponent(path).replace(/%2F/g, '/');
  const data = await githubRequest(token, 'DELETE', `/repos/${repo.owner}/${repo.name}/contents/${encodedPath}`, {
    message: `Delete ${path} (via Pages CMS)`,
    sha: body.sha,
    branch,
  });
  return data;
};

export const renameFileInRepo = async ({ env, body }) => {
  const { repo, token } = await getProxyContext(env, body);
  const oldPath = assertAllowedPath(body.oldPath || '', env);
  const newPath = assertAllowedPath(body.newPath || '', env);
  const branch = body.branch || repo.branch;
  const oldEncoded = encodeURIComponent(oldPath).replace(/%2F/g, '/');
  const oldData = await githubRequest(token, 'GET', `/repos/${repo.owner}/${repo.name}/contents/${oldEncoded}`, null, { ref: branch });

  const newEncoded = encodeURIComponent(newPath).replace(/%2F/g, '/');
  const saved = await githubRequest(token, 'PUT', `/repos/${repo.owner}/${repo.name}/contents/${newEncoded}`, {
    message: `Rename ${oldPath} to ${newPath} (via Pages CMS)`,
    content: oldData.content,
    branch,
  });

  await githubRequest(token, 'DELETE', `/repos/${repo.owner}/${repo.name}/contents/${oldEncoded}`, {
    message: `Delete ${oldPath} (via Pages CMS)`,
    sha: oldData.sha,
    branch,
  });
  return saved;
};
