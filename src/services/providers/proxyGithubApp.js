import axios from 'axios';

const DEFAULT_BASE_PATH = '/api/proxy/github_app/v1';
const BOOTSTRAP_CACHE_TTL_MS = 30 * 1000;

let basePath = DEFAULT_BASE_PATH;
let bootstrapCache = null;
let bootstrapCacheTime = 0;
let bootstrapInFlight = null;

const buildUrl = (path) => `${basePath}${path}`;

const getBootstrap = async (force = false) => {
  const now = Date.now();
  if (!force && bootstrapCache && (now - bootstrapCacheTime) < BOOTSTRAP_CACHE_TTL_MS) {
    return bootstrapCache;
  }

  if (!force && bootstrapInFlight) {
    return bootstrapInFlight;
  }

  bootstrapInFlight = axios.get(buildUrl('/bootstrap'))
    .then((res) => {
      bootstrapCache = res.data;
      bootstrapCacheTime = Date.now();
      return bootstrapCache;
    })
    .finally(() => {
      bootstrapInFlight = null;
    });

  return bootstrapInFlight;
};

const setBasePath = (value) => {
  if (value && typeof value === 'string') {
    basePath = value;
    bootstrapCache = null;
    bootstrapCacheTime = 0;
    bootstrapInFlight = null;
  }
};

const getProfile = async () => {
  const data = await getBootstrap();
  const roles = Array.isArray(data?.auth?.roles) && data.auth.roles.length > 0
    ? data.auth.roles
    : [data?.auth?.isAdmin ? 'admin' : 'editor'];
  return { email: data?.auth?.email || '', role: roles[0], roles };
};

const getOrganizations = async () => [];
const searchRepos = async (token, query = '') => {
  const data = await getBootstrap();
  const owner = data?.repo?.owner || '';
  const name = data?.repo?.name || '';
  const fullName = owner && name ? `${owner}/${name}` : '';
  const q = String(query || '').trim().toLowerCase();
  if (!fullName) return { items: [] };
  if (q && !fullName.toLowerCase().includes(q) && !name.toLowerCase().includes(q) && !owner.toLowerCase().includes(q)) {
    return { items: [] };
  }
  return {
    items: [
      {
        id: fullName,
        name,
        full_name: fullName,
        owner: { login: owner },
        private: true,
        default_branch: data?.repo?.branch || 'main',
        description: 'Proxy repository',
        pushed_at: new Date().toISOString(),
        permissions: { push: true },
      },
    ],
  };
};
const getRepo = async () => {
  const data = await getBootstrap();
  const owner = data?.repo?.owner || '';
  const name = data?.repo?.name || '';
  const fullName = owner && name ? `${owner}/${name}` : '';
  return {
    full_name: fullName,
    owner: { login: owner },
    name,
    default_branch: data?.repo?.branch || 'main',
    permissions: { push: true },
  };
};
const copyRepoTemplate = async () => null;
const getBranch = async (token, owner, repo, branch) => ({
  name: branch,
  protected: false,
});
const getBranches = async () => {
  const data = await getBootstrap();
  return [{ name: data?.repo?.branch || 'main', protected: false }];
};
const createBranch = async () => null;

const getContents = async (token, owner, repo, branch = 'HEAD', path = '') => {
  const res = await axios.get(buildUrl('/files/list'), { params: { owner, repo, branch, path } });
  return res.data;
};

const getFile = async (token, owner, repo, branch = null, path, raw = false) => {
  const res = await axios.get(buildUrl('/files/get'), { params: { owner, repo, branch, path, raw } });
  return res.data;
};

const getCommits = async (token, owner, repo, branch, path) => {
  const res = await axios.get(buildUrl('/files/commits'), { params: { owner, repo, branch, path } });
  return res.data;
};

const saveFile = async (token, owner, repo, branch, path, content, sha = null, retryCreate = false) => {
  const res = await axios.post(buildUrl('/files/save'), { owner, repo, branch, path, content, sha, retryCreate });
  return res.data;
};

const renameFile = async (token, owner, repo, branch, oldPath, newPath) => {
  const res = await axios.post(buildUrl('/files/rename'), { owner, repo, branch, oldPath, newPath });
  return res.data;
};

const deleteFile = async (token, owner, repo, branch, path, sha) => {
  const res = await axios.post(buildUrl('/files/delete'), { owner, repo, branch, path, sha });
  return res.data;
};

const logout = async () => {};

export default {
  setBasePath,
  getBootstrap,
  getProfile,
  getOrganizations,
  searchRepos,
  getRepo,
  copyRepoTemplate,
  getBranch,
  getBranches,
  createBranch,
  getContents,
  getFile,
  getCommits,
  saveFile,
  renameFile,
  deleteFile,
  logout,
};
