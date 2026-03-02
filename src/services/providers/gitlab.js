import axios from 'axios';

const apiBase = import.meta.env.VITE_GITLAB_API_BASE || 'https://gitlab.com/api/v4';
const gitlabBase = import.meta.env.VITE_GITLAB_BASE || 'https://gitlab.com';

const authHeaders = (token) => ({ Authorization: `Bearer ${token}` });
const projectPath = (owner, repo) => encodeURIComponent(`${owner}/${repo}`);
const decodeBase64Utf8 = (b64) => {
  try {
    const bytes = Uint8Array.from(atob(b64 || ''), c => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return '';
  }
};

const getProfile = async (token) => {
  const res = await axios.get(`${apiBase}/user`, { headers: authHeaders(token) });
  return res.data;
};

const getOrganizations = async (token) => {
  const res = await axios.get(`${apiBase}/groups`, { headers: authHeaders(token) });
  return res.data;
};

const mapProject = (p) => {
  // Normalize to GitHub-like shape used by UI
  const owner = p.namespace?.full_path || p.namespace?.path || '';
  // membership=true で取得しているため基本は編集権ありとみなす
  const pushAllowed =
    (p.permissions?.project_access?.access_level ?? 0) >= 30 ||
    (p.permissions?.group_access?.access_level ?? 0) >= 30 ||
    p.namespace?.kind === 'user' || // 自分の個人namespace
    true; // 最低でも member は true にしておく
  return {
    id: p.id,
    name: p.name,
    full_name: p.path_with_namespace,
    owner: { login: owner },
    private: p.visibility !== 'public',
    default_branch: p.default_branch,
    description: p.description,
    pushed_at: p.last_activity_at,
    permissions: { push: pushAllowed },
  };
};

const searchRepos = async (token, query) => {
  const baseParams = {
    membership: true,
    simple: true,
    per_page: 50,
    order_by: 'last_activity_at',
    sort: 'desc',
    search_namespaces: true, // include namespace (user/group) in search
  };
  const params = query ? { ...baseParams, search: query } : baseParams;
  const res = await axios.get(`${apiBase}/projects`, { params, headers: authHeaders(token) });
  return { items: res.data.map(mapProject) };
};

const getRepo = async (token, owner, name) => {
  const res = await axios.get(`${apiBase}/projects/${projectPath(owner, name)}`, { headers: authHeaders(token) });
  return res.data;
};

const copyRepoTemplate = async () => null; // not supported; hidden in UI when provider is gitlab

const getBranch = async (token, owner, name, branch) => {
  const res = await axios.get(`${apiBase}/projects/${projectPath(owner, name)}/repository/branches/${encodeURIComponent(branch)}`, { headers: authHeaders(token) });
  return res.data;
};

const getBranches = async (token, owner, name, perPage = 100, page = 1) => {
  const res = await axios.get(`${apiBase}/projects/${projectPath(owner, name)}/repository/branches`, { params: { per_page: perPage, page }, headers: authHeaders(token) });
  return res.data;
};

const createBranch = async (token, owner, repo, baseBranch, newBranchName) => {
  const res = await axios.post(`${apiBase}/projects/${projectPath(owner, repo)}/repository/branches`, { branch: newBranchName, ref: baseBranch }, { headers: authHeaders(token) });
  return res.data;
};

const getFile = async (token, owner, repo, branch = 'HEAD', path, raw = false) => {
  const base = `${apiBase}/projects/${projectPath(owner, repo)}/repository/files/${encodeURIComponent(path)}`;
  if (raw) {
    const res = await axios.get(`${base}/raw`, { params: { ref: branch }, headers: authHeaders(token) });
    return res.data;
  }
  const res = await axios.get(base, { params: { ref: branch }, headers: authHeaders(token) });
  return {
    content: res.data.content, // base64 encoded
    sha: res.data.last_commit_id,
    path: res.data.file_path,
    name: res.data.file_name,
    size: res.data.size,
    encoding: res.data.encoding,
  };
};

const getContents = async (token, owner, repo, branch = 'HEAD', path = '') => {
  // Single-level tree listing with pagination; fetch blob content to mimic GitHub GraphQL shape
  let page = 1;
  const perPage = 100;
  let items = [];
  while (true) {
    const res = await axios.get(`${apiBase}/projects/${projectPath(owner, repo)}/repository/tree`, {
      params: { path, ref: branch, per_page: perPage, page },
      headers: authHeaders(token),
    });
    items = items.concat(res.data || []);
    if (!res.data || res.data.length < perPage) break;
    page++;
  }

  const entries = await Promise.all(items.map(async (item) => {
    if (item.type === 'blob') {
      const file = await getFile(token, owner, repo, branch, item.path);
      const text = decodeBase64Utf8(file.content || '');
      return {
        name: item.name,
        path: item.path,
        type: 'blob',
        object: { text, oid: file.sha },
      };
    }
    return { name: item.name, path: item.path, type: 'tree' };
  }));
  return entries;
};

const getCommits = async (token, owner, repo, branch, path) => {
  const res = await axios.get(`${apiBase}/projects/${projectPath(owner, repo)}/repository/commits`, { params: { ref_name: branch, path }, headers: authHeaders(token) });
  return res.data;
};

const saveFile = async (token, owner, repo, branch, path, content, sha = null) => {
  const method = sha ? 'put' : 'post';
  const url = `${apiBase}/projects/${projectPath(owner, repo)}/repository/files/${encodeURIComponent(path)}`;
  const res = await axios({
    method,
    url,
    headers: authHeaders(token),
    data: {
      branch,
      content,
      encoding: 'base64',
      commit_message: `${sha ? 'Update' : 'Create'} ${path} (via Pages CMS)`,
      ...(sha ? { last_commit_id: sha } : {}),
    },
  });
  // Normalize to GitHub-like shape expected by callers (content.path / content.sha)
  return {
    content: {
      path: res.data.file_path || path,
      sha: res.data.last_commit_id || res.data.content_sha || res.data.commit_id || null,
    },
  };
};

const deleteFile = async (token, owner, repo, branch, path, sha) => {
  const url = `${apiBase}/projects/${projectPath(owner, repo)}/repository/files/${encodeURIComponent(path)}`;
  const res = await axios.delete(url, { headers: authHeaders(token), data: { branch, commit_message: `Delete ${path} (via Pages CMS)`, last_commit_id: sha } });
  return res.data;
};

const renameFile = async (token, owner, repo, branch, oldPath, newPath) => {
  // GitLab supports previous_path for move
  const url = `${apiBase}/projects/${projectPath(owner, repo)}/repository/files/${encodeURIComponent(newPath)}`;
  const file = await getFile(token, owner, repo, branch, oldPath);
  const res = await axios.put(url, {
    branch,
    content: file.content,
    encoding: 'base64',
    commit_message: `Rename ${oldPath} to ${newPath}`,
    previous_path: oldPath,
  }, { headers: authHeaders(token) });
  return res.data;
};

const logout = async () => {};

export default { getProfile, getOrganizations, searchRepos, getRepo, copyRepoTemplate, getBranch, getBranches, createBranch, getContents, getFile, getCommits, saveFile, renameFile, deleteFile, logout };
