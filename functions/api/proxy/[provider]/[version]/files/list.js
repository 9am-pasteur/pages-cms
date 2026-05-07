import { getAccessContext } from '../../../../../lib/access-auth';
import { jsonResponse, respondWithMappedError } from '../../../../../lib/api-errors';
import { listFiles } from '../../../../../lib/proxy-github-app';

export async function onRequestGet({ request, env, params }) {
  if (params.provider !== 'github_app' || params.version !== 'v1') {
    return jsonResponse({ error: 'NOT_FOUND' }, 404);
  }

  try {
    const access = await getAccessContext(request, env);
    if (!access.accessEnabled) {
      return jsonResponse({ error: 'FORBIDDEN', message: 'Cloudflare Access mode is disabled' }, 403);
    }

    const url = new URL(request.url);
    const data = await listFiles({
      env,
      query: {
        owner: url.searchParams.get('owner') || '',
        repo: url.searchParams.get('repo') || '',
        branch: url.searchParams.get('branch') || '',
        path: url.searchParams.get('path') || '',
      },
    });

    return jsonResponse(data);
  } catch (error) {
    return respondWithMappedError(error);
  }
}
