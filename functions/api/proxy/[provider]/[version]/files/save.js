import { getAccessContext } from '../../../../../lib/access-auth';
import { jsonResponse, respondWithMappedError } from '../../../../../lib/api-errors';
import { saveFileToRepo } from '../../../../../lib/proxy-github-app';

export async function onRequestPost({ request, env, params }) {
  if (params.provider !== 'github_app' || params.version !== 'v1') {
    return jsonResponse({ error: 'NOT_FOUND' }, 404);
  }

  try {
    const access = await getAccessContext(request, env);
    if (!access.accessEnabled) {
      return jsonResponse({ error: 'FORBIDDEN', message: 'Cloudflare Access mode is disabled' }, 403);
    }

    const body = await request.json();
    const data = await saveFileToRepo({ env, body });
    return jsonResponse(data);
  } catch (error) {
    return respondWithMappedError(error);
  }
}
