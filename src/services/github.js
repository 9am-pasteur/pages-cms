/**
 * Provider-agnostic git service facade. Keeps token in localStorage and delegates
 * to provider-specific implementations (GitHub, GitLab).
 */
import { ref } from 'vue';
import axios from 'axios';
import router from '@/router';
import notifications from '@/services/notifications';
import providers from '@/config/providers';
import githubProvider from '@/services/providers/github';
import gitlabProvider from '@/services/providers/gitlab';
import proxyGithubAppProvider from '@/services/providers/proxyGithubApp';

const providerMap = {
  github: githubProvider,
  gitlab: gitlabProvider,
  proxy_github_app: proxyGithubAppProvider,
};

const providerId = ref(localStorage.getItem('provider') || 'github');
const token = ref(localStorage.getItem('token') || null);
const profile = ref(null);
let runtimeConfigLoaded = false;
let runtimeConfigPromise = null;
let bootstrapCache = null;
let bootstrapCacheTime = 0;
const bootstrapCacheTtlMs = 30 * 1000;

const getProviderConfig = (id) => providers.find((p) => p.id === id);
const currentProvider = () => providerMap[providerId.value] || githubProvider;
const currentProviderConfig = () => getProviderConfig(providerId.value) || providers[0];

const setProvider = (id) => {
  if (providerMap[id]) {
    providerId.value = id;
    localStorage.setItem('provider', id);
    // flush profile cache when switching provider
    profile.value = null;
  }
};

const setToken = (value, id = providerId.value) => {
  token.value = value;
  setProvider(id);
  localStorage.setItem('token', value);
};

const clearToken = () => {
  token.value = null;
  localStorage.removeItem('token');
};

const handleAuthError = () => {
  notifications.notify('Your token is invalid or has expired. Please log in again.', 'error', { delay: 0 });
  clearToken();
  router.push({ name: 'login' });
};

const extractErrorPayload = (error) => {
  const data = error?.response?.data;
  if (!data) return { message: '' };
  if (typeof data === 'string') return { message: data };
  return {
    message: data.message || data.error || '',
    hint: data.hint || '',
    check: Array.isArray(data.check) ? data.check : [],
  };
};

const composeErrorNotification = (payload) => {
  const lines = [];
  if (payload.message) lines.push(payload.message);
  if (payload.hint) lines.push(payload.hint);
  if (payload.check?.length) lines.push(`Check: ${payload.check.join(', ')}`);
  return lines.filter(Boolean).join(' ');
};

const handleForbiddenError = (error) => {
  const payload = extractErrorPayload(error);
  const message = String(payload.message || '').toLowerCase();
  if (message.includes('path is not writable in proxy mode') || message.includes('path is not allowed')) {
    notifications.notify('This file can only be edited by administrators.', 'warning');
    return;
  }
  const detail = composeErrorNotification(payload);
  notifications.notify(detail || 'You do not have permission to perform this action.', 'warning');
};

const withCatch = async (fn, options = {}) => {
  try {
    return await fn();
  } catch (error) {
    const status = error?.response?.status;
    const suppressStatuses = Array.isArray(options.suppressStatuses) ? options.suppressStatuses : [];
    if (suppressStatuses.includes(status)) {
      return null;
    }
    if (status === 401) {
      handleAuthError();
    } else if (status === 403) {
      handleForbiddenError(error);
    } else if (status >= 400) {
      const detail = composeErrorNotification(extractErrorPayload(error));
      if (detail) {
        notifications.notify(detail, 'error');
      }
    }
    console.error(error);
    return null;
  }
};

// === Delegated API ===
const getProfile = () => withCatch(async () => {
  if (profile.value) return profile.value;
  const res = await currentProvider().getProfile(token.value);
  profile.value = res;
  return profile.value;
});

const getOrganizations = () => withCatch(() => currentProvider().getOrganizations(token.value));
const searchRepos = (query, writeAccessOnly = false) => withCatch(() => currentProvider().searchRepos(token.value, query, writeAccessOnly));
const getRepo = (owner, name) => withCatch(() => currentProvider().getRepo(token.value, owner, name));
const copyRepoTemplate = (...args) => withCatch(() => currentProvider().copyRepoTemplate(token.value, ...args));
const getBranch = (owner, name, branch) => withCatch(() => currentProvider().getBranch(token.value, owner, name, branch));
const getBranches = (owner, name, perPage = 100, page = 1) => withCatch(() => currentProvider().getBranches(token.value, owner, name, perPage, page));
const createBranch = (owner, repo, baseBranch, newBranchName) => withCatch(() => currentProvider().createBranch(token.value, owner, repo, baseBranch, newBranchName));
const getContents = (owner, repo, branch = 'HEAD', path = '', useGraphql = true, options = {}) => withCatch(() => currentProvider().getContents(token.value, owner, repo, branch, path, useGraphql), options);
const getFile = (owner, repo, branch = null, path, raw = false, options = {}) => withCatch(() => currentProvider().getFile(token.value, owner, repo, branch, path, raw), options);
const getCommits = (owner, repo, branch, path, options = {}) => withCatch(() => currentProvider().getCommits(token.value, owner, repo, branch, path), options);
const saveFile = (owner, repo, branch, path, content, sha = null, retryCreate = false) => withCatch(() => currentProvider().saveFile(token.value, owner, repo, branch, path, content, sha, retryCreate));
const renameFile = (owner, repo, branch, oldPath, newPath) => withCatch(() => currentProvider().renameFile(token.value, owner, repo, branch, oldPath, newPath));
const deleteFile = (owner, repo, branch, path, sha) => withCatch(() => currentProvider().deleteFile(token.value, owner, repo, branch, path, sha));
const logout = async () => {
  await currentProvider().logout?.(token.value);
  clearToken();
};

// Exchange authorization code for token using PKCE (no client secret needed)
const exchangeCode = async (code) => {
  await ensureRuntimeConfig();
  const storedProvider = sessionStorage.getItem('provider') || providerId.value || 'github';
  const cfg = getProviderConfig(storedProvider);
  if (!cfg?.oauth?.tokenUrl || !cfg.oauth.clientId) {
    throw new Error('OAuth provider not configured');
  }
  const verifier = sessionStorage.getItem('pkce_verifier');
  let accessToken;
  if (storedProvider === 'github') {
    // GitHub token endpoint lacks CORS; proxy through our function
    const res = await axios.post('/api/github-token', {
      code,
      code_verifier: cfg.oauth.pkce ? verifier : undefined,
      redirect_uri: cfg.oauth.redirectUri || `${window.location.origin}/auth/callback`,
    });
    accessToken = res.data.access_token;
  } else {
    const body = new URLSearchParams({
      client_id: cfg.oauth.clientId,
      grant_type: 'authorization_code',
      code,
      redirect_uri: cfg.oauth.redirectUri,
    });
    if (cfg.oauth.pkce && verifier) {
      body.append('code_verifier', verifier);
    }
    const res = await axios.post(cfg.oauth.tokenUrl, body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
    });
    accessToken = res.data.access_token;
  }
  if (accessToken) {
    setToken(accessToken, storedProvider);
  }
  return accessToken;
};

const ensureRuntimeConfig = async () => {
  if (runtimeConfigLoaded) return;
  if (runtimeConfigPromise) return runtimeConfigPromise;
  runtimeConfigPromise = (async () => {
    try {
      const res = await fetch('/api/provider-config');
      if (res.ok) {
        const data = await res.json();
        providers.forEach((p) => {
          const runtime = data[p.id];
          if (runtime) {
            if (runtime.clientId) p.oauth.clientId = runtime.clientId;
            if (runtime.redirectUri) p.oauth.redirectUri = runtime.redirectUri;
            if (runtime.base && p.id === 'gitlab') {
              p.links.profile = (user) => `${runtime.base}/${user}`;
              p.links.repo = (owner, repo) => `${runtime.base}/${owner}/${repo}`;
              p.links.file = (owner, repo, branch, path) => `${runtime.base}/${owner}/${repo}/-/blob/${branch}/${path}`;
              p.links.folder = (owner, repo, branch, path) => `${runtime.base}/${owner}/${repo}/-/tree/${branch}/${path}`;
              p.links.rawFile = (owner, repo, branch, path) => `${runtime.base}/${owner}/${repo}/-/raw/${branch}/${path}`;
              if (runtime.apiBase) {
                p.apiBase = runtime.apiBase;
              }
            }
          }
        });
      }
    } catch (e) {
      console.warn('provider-config fetch failed', e);
    } finally {
      runtimeConfigLoaded = true;
    }
  })();
  return runtimeConfigPromise;
};

/**
 * @returns {Promise<import('@/types/bootstrap').BootstrapResponse>}
 */
const getBootstrap = async (force = false) => {
  const now = Date.now();
  if (!force && bootstrapCache && (now - bootstrapCacheTime) < bootstrapCacheTtlMs) {
    return bootstrapCache;
  }
  const res = await axios.get('/api/bootstrap');
  bootstrapCache = res.data;
  bootstrapCacheTime = now;
  const proxyMode = (bootstrapCache.modes || []).find((mode) => mode.id === 'proxy_github_app');
  if (proxyMode?.proxy?.basePath) {
    proxyGithubAppProvider.setBasePath(proxyMode.proxy.basePath);
  }
  return bootstrapCache;
};

const getBootstrapSafe = async (force = false) => {
  try {
    return await getBootstrap(force);
  } catch {
    return null;
  }
};

const syncProviderWithBootstrap = async () => {
  const bootstrap = await getBootstrapSafe();
  if (!bootstrap) return null;
  const allowed = Array.isArray(bootstrap.allowedModes) ? bootstrap.allowedModes : [];
  if (allowed.length === 0) return bootstrap;
  if (!allowed.includes(providerId.value)) {
    const fallback = bootstrap.defaultMode || allowed[0];
    setProvider(fallback);
    if (fallback === 'proxy_github_app') {
      clearToken();
    }
  }
  return bootstrap;
};

const getProxyBootstrap = async () => {
  return proxyGithubAppProvider.getBootstrap();
};

export default { token, profile, providerId, providers, currentProviderConfig, setProvider, setToken, clearToken, getProfile, getOrganizations, searchRepos, getRepo, copyRepoTemplate, getBranch, getBranches, createBranch, getContents, getFile, getCommits, saveFile, renameFile, deleteFile, logout, exchangeCode, ensureRuntimeConfig, getBootstrap, getBootstrapSafe, syncProviderWithBootstrap, getProxyBootstrap };
