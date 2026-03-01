// Provider configuration for GitHub and GitLab. Values can be overridden via Vite env vars.
const githubApi = import.meta.env.VITE_GITHUB_API_BASE || 'https://api.github.com';
const gitlabApi = import.meta.env.VITE_GITLAB_API_BASE || 'https://gitlab.com/api/v4';

const gitlabBase = import.meta.env.VITE_GITLAB_BASE || 'https://gitlab.com';

const providers = [
  {
    id: 'github',
    label: 'GitHub',
    apiBase: githubApi,
    rawBase: import.meta.env.VITE_GITHUB_RAW_BASE || 'https://raw.githubusercontent.com',
    oauth: {
      authorizeUrl: 'https://github.com/login/oauth/authorize',
      tokenUrl: 'https://github.com/login/oauth/access_token',
      clientId: '', // runtime override via /api/provider-config
      redirectUri: '', // runtime override
      scopes: ['repo', 'read:user'],
      pkce: false, // use client_secret via function proxy to avoid verifier issues
    },
    pat: {
      hint: 'GitHub personal access token (repo/write contents)',
      regex: /^(ghp_|github_pat_)/i,
      scopes: ['repo'],
    },
    links: {
      revoke: 'https://github.com/settings/connections/applications',
      profile: (user) => `https://github.com/${user}`,
      repo: (owner, repo) => `https://github.com/${owner}/${repo}`,
      file: (owner, repo, branch, path) => `https://github.com/${owner}/${repo}/blob/${branch}/${path}`,
      folder: (owner, repo, branch, path) => `https://github.com/${owner}/${repo}/tree/${branch}/${path}`,
      rawFile: (owner, repo, branch, path) => `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`,
    },
  },
  {
    id: 'gitlab',
    label: 'GitLab',
    apiBase: gitlabApi,
    rawBase: import.meta.env.VITE_GITLAB_RAW_BASE || gitlabBase,
    oauth: {
      authorizeUrl: `${gitlabBase}/oauth/authorize`,
      tokenUrl: `${gitlabBase}/oauth/token`,
      clientId: '', // runtime override via /api/provider-config
      redirectUri: '', // runtime override
      scopes: ['api'],
      pkce: true,
    },
    pat: {
      hint: 'GitLab personal access token (api scope or read/write_repository)',
      regex: /^[A-Za-z0-9_\-]{15,}$/,
      scopes: ['api'],
    },
    links: {
      revoke: `${gitlabBase}/-/profile/applications`,
      profile: (user) => `${gitlabBase}/${user}`,
      repo: (owner, repo) => `${gitlabBase}/${owner}/${repo}`,
      file: (owner, repo, branch, path) => `${gitlabBase}/${owner}/${repo}/-/blob/${branch}/${path}`,
      folder: (owner, repo, branch, path) => `${gitlabBase}/${owner}/${repo}/-/tree/${branch}/${path}`,
      rawFile: (owner, repo, branch, path) => `${gitlabBase}/${owner}/${repo}/-/raw/${branch}/${path}`,
    },
  },
];

export default providers;
