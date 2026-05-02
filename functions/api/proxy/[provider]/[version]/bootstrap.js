import {
  getAccessContext,
  getProxyRepoConfig,
  resolvePathPolicy,
} from '../../../../lib/access-auth';

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

export async function onRequestGet({ request, env, params }) {
  const { provider, version } = params;
  if (provider !== 'github_app' || version !== 'v1') {
    return json({ error: 'NOT_FOUND' }, 404);
  }

  try {
    const access = await getAccessContext(request, env);
    if (!access.accessEnabled) {
      return json({ error: 'FORBIDDEN', message: 'Cloudflare Access mode is disabled' }, 403);
    }

    return json({
      provider: 'github_app',
      version: 'v1',
      auth: {
        email: access.email,
        isAdmin: access.isAdmin,
      },
      repo: getProxyRepoConfig(env),
      pathPolicy: resolvePathPolicy(env),
      features: {
        // proxy mode must not expose settings mutations
        canEditConfig: false,
      },
    });
  } catch (error) {
    return json(
      {
        error: 'UNAUTHORIZED',
        message: error.message || 'Unauthorized',
      },
      401
    );
  }
}

