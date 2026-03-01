export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json();
    const { code, code_verifier, redirect_uri } = body || {};
    if (!code) return new Response('Missing code', { status: 400 });

    const client_id = env.GITHUB_CLIENT_ID || env.VITE_GITHUB_CLIENT_ID;
    const client_secret = env.GITHUB_CLIENT_SECRET || env.VITE_GITHUB_CLIENT_SECRET; // optional for PKCE
    if (!client_id) return new Response('Missing client_id', { status: 500 });

    const params = new URLSearchParams({
      client_id,
      code,
      redirect_uri: redirect_uri || env.OAUTH_REDIRECT || env.BASE_URL || `${new URL(request.url).origin}/auth/callback`,
      grant_type: 'authorization_code'
    });
    if (code_verifier) params.append('code_verifier', code_verifier);
    if (client_secret) params.append('client_secret', client_secret);

    const ghRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: params.toString()
    });

    const data = await ghRes.json();
    return new Response(JSON.stringify(data), { status: ghRes.status, headers: { 'Content-Type': 'application/json' } });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
}
