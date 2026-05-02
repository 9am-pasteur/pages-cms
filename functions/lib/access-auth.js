const CERTS_CACHE_TTL_MS = 5 * 60 * 1000;

let certsCache = {
  fetchedAt: 0,
  keys: [],
};

const textEncoder = new TextEncoder();

const base64urlToBytes = (value) => {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  const decoded = atob(padded);
  return Uint8Array.from(decoded, (ch) => ch.charCodeAt(0));
};

const base64urlToJson = (value) => {
  const bytes = base64urlToBytes(value);
  return JSON.parse(new TextDecoder().decode(bytes));
};

const getAllowedAudiences = (env) =>
  (env.CLOUDFLARE_ACCESS_AUD || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);

const nowInSeconds = () => Math.floor(Date.now() / 1000);

const parseTeamDomain = (env) => {
  const raw = (env.CLOUDFLARE_ACCESS_TEAM_DOMAIN || '').trim();
  if (!raw) return '';
  return raw
    .replace(/^https?:\/\//i, '')
    .replace(/\/+$/, '');
};

const getExpectedIssuer = (env) => {
  const explicit = (env.CLOUDFLARE_ACCESS_ISSUER || '').trim();
  if (explicit) return explicit;
  const domain = parseTeamDomain(env);
  return domain ? `https://${domain}` : '';
};

const getCerts = async (env) => {
  const teamDomain = parseTeamDomain(env);
  if (!teamDomain) {
    throw new Error('CLOUDFLARE_ACCESS_TEAM_DOMAIN is required');
  }

  const now = Date.now();
  if (certsCache.keys.length > 0 && now - certsCache.fetchedAt < CERTS_CACHE_TTL_MS) {
    return certsCache.keys;
  }

  const res = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`);
  if (!res.ok) {
    throw new Error(`Failed to fetch access certs: ${res.status}`);
  }

  const body = await res.json();
  const keys = Array.isArray(body?.keys) ? body.keys : [];
  certsCache = { fetchedAt: now, keys };
  return keys;
};

const verifyJwtSignature = async (token, env) => {
  const segments = token.split('.');
  if (segments.length !== 3) {
    throw new Error('Malformed JWT');
  }

  const [headerRaw, payloadRaw, signatureRaw] = segments;
  const header = base64urlToJson(headerRaw);
  const payload = base64urlToJson(payloadRaw);
  const signature = base64urlToBytes(signatureRaw);

  if (header.alg !== 'RS256') {
    throw new Error(`Unsupported JWT alg: ${header.alg}`);
  }

  const keys = await getCerts(env);
  const key = keys.find((item) => item.kid === header.kid) || keys[0];
  if (!key) {
    throw new Error('No verification key found');
  }

  const cryptoKey = await crypto.subtle.importKey(
    'jwk',
    key,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );

  const data = textEncoder.encode(`${headerRaw}.${payloadRaw}`);
  const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, signature, data);
  if (!valid) {
    throw new Error('Invalid JWT signature');
  }

  return { header, payload };
};

const assertJwtClaims = (payload, env) => {
  const now = nowInSeconds();
  if (typeof payload.exp === 'number' && payload.exp <= now) {
    throw new Error('JWT expired');
  }
  if (typeof payload.nbf === 'number' && payload.nbf > now) {
    throw new Error('JWT not valid yet');
  }

  const expectedIssuer = getExpectedIssuer(env);
  if (expectedIssuer && payload.iss !== expectedIssuer) {
    throw new Error('JWT issuer mismatch');
  }

  const allowedAudiences = getAllowedAudiences(env);
  if (allowedAudiences.length > 0) {
    const aud = payload.aud;
    const audiences = Array.isArray(aud) ? aud : [aud];
    const matched = audiences.some((entry) => allowedAudiences.includes(entry));
    if (!matched) {
      throw new Error('JWT audience mismatch');
    }
  }
};

const normalizeEmail = (email) => (email || '').trim().toLowerCase();

const getAdminUsers = (env) =>
  (env.CMS_ADMIN_USERS || '')
    .split(',')
    .map(normalizeEmail)
    .filter(Boolean);

const getDenyUsers = (env) =>
  (env.CMS_DENY_USERS || '')
    .split(',')
    .map(normalizeEmail)
    .filter(Boolean);

const isAccessEnabled = (env) => Boolean(env.CLOUDFLARE_ACCESS_TEAM_DOMAIN);

export const verifyAccessJwtFromRequest = async (request, env) => {
  const token = request.headers.get('Cf-Access-Jwt-Assertion') || '';
  if (!token) {
    throw new Error('Missing Access JWT');
  }

  const { payload } = await verifyJwtSignature(token, env);
  assertJwtClaims(payload, env);

  const email = normalizeEmail(payload.email || payload.sub || '');
  if (!email) {
    throw new Error('Missing email claim');
  }

  const denyUsers = getDenyUsers(env);
  if (denyUsers.includes(email)) {
    throw new Error('User denied');
  }

  const adminUsers = getAdminUsers(env);
  return {
    email,
    isAdmin: adminUsers.includes(email),
    payload,
  };
};

export const resolvePathPolicy = (env) => {
  const splitCsv = (value) =>
    (value || '')
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean);

  const allowed = splitCsv(env.CMS_PROXY_ALLOWED_PATHS || 'content/articles/**,content/assets/**');
  const denied = splitCsv(env.CMS_PROXY_DENIED_PATHS || '.cms/**,.github/**,scripts/**,config/**,package.json');
  return { allowed, denied };
};

export const getProxyRepoConfig = (env) => ({
  owner: env.GITHUB_REPO_OWNER || '',
  name: env.GITHUB_REPO_NAME || '',
  branch: env.GITHUB_BRANCH || 'main',
});

export const getAccessContext = async (request, env) => {
  if (!isAccessEnabled(env)) {
    return { accessEnabled: false, email: '', isAdmin: false };
  }

  const identity = await verifyAccessJwtFromRequest(request, env);
  return {
    accessEnabled: true,
    email: identity.email,
    isAdmin: identity.isAdmin,
  };
};

export const getModePolicy = (accessContext, env) => {
  const canUseGithubDirect = Boolean(env.GITHUB_CLIENT_ID || env.VITE_GITHUB_CLIENT_ID);
  const canUseGitlabDirect = Boolean(env.GITLAB_CLIENT_ID || env.VITE_GITLAB_CLIENT_ID);

  const modes = [];
  if (canUseGithubDirect) {
    modes.push({ id: 'github', type: 'direct', label: 'GitHub', enabled: true });
  }
  if (canUseGitlabDirect) {
    modes.push({ id: 'gitlab', type: 'direct', label: 'GitLab', enabled: true });
  }
  modes.push({
    id: 'proxy_github_app',
    type: 'proxy',
    label: 'Proxy (GitHub App)',
    enabled: true,
    proxy: {
      provider: 'github_app',
      version: 'v1',
      basePath: '/api/proxy/github_app/v1',
    },
  });

  if (!accessContext.accessEnabled) {
    const allowedModes = modes.filter((mode) => mode.type === 'direct').map((mode) => mode.id);
    const defaultMode = allowedModes[0] || 'proxy_github_app';
    return { modes, allowedModes, defaultMode };
  }

  if (!accessContext.isAdmin) {
    return {
      modes,
      allowedModes: ['proxy_github_app'],
      defaultMode: 'proxy_github_app',
    };
  }

  const allowedModes = modes.map((mode) => mode.id);
  return {
    modes,
    allowedModes,
    defaultMode: 'proxy_github_app',
  };
};

