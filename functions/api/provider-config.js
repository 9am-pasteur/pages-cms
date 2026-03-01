export async function onRequestGet({ env }) {
  const base =
    env.OAUTH_REDIRECT ||
    env.BASE_URL ||
    env.VITE_OAUTH_REDIRECT ||
    '';
  const normalizeBase = (url) => url ? url.replace(/\/$/, '') : '';
  const redirect = base ? `${normalizeBase(base)}/auth/callback` : '';
  const gitlabBase = env.GITLAB_BASE || env.VITE_GITLAB_BASE || 'https://gitlab.com';
  const gitlabApiBase = env.GITLAB_API_BASE || env.VITE_GITLAB_API_BASE || 'https://gitlab.com/api/v4';

  const data = {
    github: {
      clientId: env.GITHUB_CLIENT_ID || env.VITE_GITHUB_CLIENT_ID || '',
      redirectUri: redirect
    },
    gitlab: {
      clientId: env.GITLAB_CLIENT_ID || env.VITE_GITLAB_CLIENT_ID || '',
      redirectUri: redirect,
      base: gitlabBase,
      apiBase: gitlabApiBase
    }
  };
  return new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json' }
  });
}
