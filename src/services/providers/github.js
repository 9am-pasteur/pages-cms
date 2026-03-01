import axios from 'axios';

const apiBase = import.meta.env.VITE_GITHUB_API_BASE || 'https://api.github.com';

const authHeaders = (token) => ({ Authorization: `Bearer ${token}` });

const getProfile = async (token) => {
  const res = await axios.get(`${apiBase}/user`, { params: { timestamp: Date.now() }, headers: authHeaders(token) });
  return res.data;
};

const getOrganizations = async (token) => {
  const res = await axios.get(`${apiBase}/user/orgs`, { params: { timestamp: Date.now() }, headers: authHeaders(token) });
  return res.data;
};

const searchRepos = async (token, query) => {
  if (!query) return { items: [] };
  const res = await axios.get(`${apiBase}/search/repositories`, { params: { q: `${query} in:name fork:true`, timestamp: Date.now() }, headers: authHeaders(token) });
  return res.data;
};

const getRepo = async (token, owner, name) => {
  const res = await axios.get(`${apiBase}/repos/${owner}/${name}`, { params: { timestamp: Date.now() }, headers: authHeaders(token) });
  return res.data;
};

const copyRepoTemplate = async (token, templateOwner, templateRepo, name, owner = null) => {
  const url = `${apiBase}/repos/${templateOwner}/${templateRepo}/generate`;
  const body = { private: true, name }; if (owner) body.owner = owner;
  const res = await axios.post(url, body, { headers: authHeaders(token) });
  return res.data;
};

const getBranch = async (token, owner, name, branch) => {
  const res = await axios.get(`${apiBase}/repos/${owner}/${name}/branches/${branch}`, { params: { timestamp: Date.now() }, headers: authHeaders(token) });
  return res.data;
};

const getBranches = async (token, owner, name, perPage = 100, page = 1) => {
  const res = await axios.get(`${apiBase}/repos/${owner}/${name}/branches`, { params: { timestamp: Date.now(), per_page: perPage, page }, headers: authHeaders(token) });
  return res.data;
};

const createBranch = async (token, owner, repo, baseBranch, newBranchName) => {
  const branchInfoUrl = `${apiBase}/repos/${owner}/${repo}/branches/${baseBranch}`;
  const branchInfo = await axios.get(branchInfoUrl, { headers: authHeaders(token) });
  const baseSha = branchInfo.data.commit.sha;
  const res = await axios.post(`${apiBase}/repos/${owner}/${repo}/git/refs`, { ref: `refs/heads/${newBranchName}`, sha: baseSha }, { headers: authHeaders(token) });
  return res.data;
};

const getContents = async (token, owner, repo, branch = 'HEAD', path = '', useGraphql = true) => {
  if (useGraphql) {
    const response = await axios.post(
      'https://api.github.com/graphql',
      {
        query: `
          query ($owner: String!, $repo: String!, $expression: String!) {
            repository(owner: $owner, name: $repo) {
              object(expression: $expression) {
                ... on Tree {
                  entries {
                    name
                    path
                    type
                    object {
                      ... on Blob {
                        text
                        oid
                      }
                    }
                  }
                }
              }
            }
          }
        `,
        variables: { owner, repo, expression: `${branch}:${path}` },
      },
      { params: { timestamp: Date.now() }, headers: authHeaders(token) }
    );
    return response.data.data.repository.object.entries;
  }
  const url = `${apiBase}/repos/${owner}/${repo}/contents/${path}`;
  const res = await axios.get(url, { params: { ref: branch, timestamp: Date.now() }, headers: authHeaders(token) });
  return res.data;
};

const getFile = async (token, owner, repo, branch = null, path, raw = false) => {
  const accept = raw ? 'application/vnd.github.v3.raw' : 'application/vnd.github.v3+json';
  const url = `${apiBase}/repos/${owner}/${repo}/contents/${path}`;
  const params = { timestamp: Date.now() }; if (branch) params.ref = branch;
  const res = await axios.get(url, { params, headers: { ...authHeaders(token), Accept: accept } });
  return res.data;
};

const getCommits = async (token, owner, repo, branch, path) => {
  const res = await axios.get(`${apiBase}/repos/${owner}/${repo}/commits`, { params: { sha: branch, path, timestamp: Date.now() }, headers: authHeaders(token) });
  return res.data;
};

const saveFile = async (token, owner, repo, branch, path, content, sha = null, retryCreate = false) => {
  let attemptsMax = retryCreate ? 5 : 1; let attempt = 0; let currentPath = path; let siblingFiles = []; let uniqueFilenameCounter = 1;
  const generateUniqueFilename = (p, siblings, attemptNum) => {
    const parts = p.split('/').filter(Boolean); const fileName = parts.pop(); const parentPath = parts.length > 0 ? parts.join('/') : '';
    const baseName = fileName.substring(0, fileName.lastIndexOf('.')); const extension = fileName.substring(fileName.lastIndexOf('.'));
    if (attemptNum === attemptsMax - 1) { const newName = `${baseName}-${Date.now()}${extension}`; return parentPath ? `${parentPath}/${newName}` : newName; }
    let newName; do { newName = `${baseName}-${uniqueFilenameCounter}${extension}`; uniqueFilenameCounter++; } while (siblings.includes(newName));
    return parentPath ? `${parentPath}/${newName}` : newName;
  };

  while (attempt < attemptsMax) {
    const url = `${apiBase}/repos/${owner}/${repo}/contents/${currentPath}`;
    try {
      const params = { message: sha ? `Update ${currentPath} (via Pages CMS)` : `Create ${currentPath} (via Pages CMS)`, content, branch }; if (sha) params.sha = sha;
      const res = await axios.put(url, params, { headers: authHeaders(token) });
      return res.data;
    } catch (error) {
      if (retryCreate && error.response && error.response.status === 422) {
        attempt++;
        if (siblingFiles.length === 0) {
          const parentPath = path.substring(0, path.lastIndexOf('/') + 1);
          const contents = await getContents(token, owner, repo, branch, parentPath, false);
          siblingFiles = Array.isArray(contents) ? contents.map((f) => f.name) : [];
        }
        currentPath = generateUniqueFilename(path, siblingFiles, attempt);
      } else {
        throw error;
      }
    }
  }
  throw new Error('Unable to save file');
};

const deleteFile = async (token, owner, repo, branch, path, sha) => {
  const url = `${apiBase}/repos/${owner}/${repo}/contents/${path}`;
  const params = { message: `Delete ${path} (via Pages CMS)`, sha, branch };
  const res = await axios.delete(url, { headers: authHeaders(token), data: params });
  return res.data;
};

// GitHub rename implemented via low-level tree rebuild; kept from legacy code would be expensive.
const renameFile = async (token, owner, repo, branch, oldPath, newPath) => {
  // fallback: copy new + delete old to preserve behavior without history (simpler than tree rewrite)
  const file = await getFile(token, owner, repo, branch, oldPath, false);
  if (!file || !file.content) return null;
  const save = await saveFile(token, owner, repo, branch, newPath, file.content);
  if (save) {
    await deleteFile(token, owner, repo, branch, oldPath, file.sha || file.sha1 || undefined);
  }
  return save;
};

const logout = async () => {};

export default { getProfile, getOrganizations, searchRepos, getRepo, copyRepoTemplate, getBranch, getBranches, createBranch, getContents, getFile, getCommits, saveFile, renameFile, deleteFile, logout };
