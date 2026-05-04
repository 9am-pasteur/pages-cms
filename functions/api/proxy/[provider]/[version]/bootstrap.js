import {
  getAccessContext,
  getProxyRepoConfig,
  resolveReadPathPolicy,
  resolveWritePathPolicy,
} from '../../../../lib/access-auth';
import { jsonResponse, respondWithMappedError } from '../../../../lib/api-errors';

export async function onRequestGet({ request, env, params }) {
  const { provider, version } = params;
  if (provider !== 'github_app' || version !== 'v1') {
    return jsonResponse({ error: 'NOT_FOUND' }, 404);
  }

  try {
    const access = await getAccessContext(request, env);
    if (!access.accessEnabled) {
      return jsonResponse({ error: 'FORBIDDEN', message: 'Cloudflare Access mode is disabled' }, 403);
    }

    return jsonResponse({
      provider: 'github_app',
      version: 'v1',
      auth: {
        email: access.email,
        isAdmin: access.isAdmin,
      },
      repo: getProxyRepoConfig(env),
      pathPolicy: {
        read: resolveReadPathPolicy(env),
        write: resolveWritePathPolicy(env),
      },
      features: {
        // proxy mode must not expose settings mutations
        canEditConfig: false,
      },
    });
  } catch (error) {
    return respondWithMappedError(error);
  }
}
