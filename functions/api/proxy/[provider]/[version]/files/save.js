import { getAccessContext } from '../../../../../lib/access-auth';
import { saveFileToRepo } from '../../../../../lib/proxy-github-app';

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

export async function onRequestPost({ request, env, params }) {
  if (params.provider !== 'github_app' || params.version !== 'v1') {
    return json({ error: 'NOT_FOUND' }, 404);
  }

  try {
    const access = await getAccessContext(request, env);
    if (!access.accessEnabled) {
      return json({ error: 'FORBIDDEN', message: 'Cloudflare Access mode is disabled' }, 403);
    }

    const body = await request.json();
    const data = await saveFileToRepo({ env, body });
    return json(data);
  } catch (error) {
    const status = /not allowed|mismatch/i.test(error.message) ? 403 : 400;
    return json({ error: 'BAD_REQUEST', message: error.message }, status);
  }
}
