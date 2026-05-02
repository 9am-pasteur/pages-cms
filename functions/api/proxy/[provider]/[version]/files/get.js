import { getAccessContext } from '../../../../../lib/access-auth';
import { getFileFromRepo } from '../../../../../lib/proxy-github-app';

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

export async function onRequestGet({ request, env, params }) {
  if (params.provider !== 'github_app' || params.version !== 'v1') {
    return json({ error: 'NOT_FOUND' }, 404);
  }

  try {
    const access = await getAccessContext(request, env);
    if (!access.accessEnabled) {
      return json({ error: 'FORBIDDEN', message: 'Cloudflare Access mode is disabled' }, 403);
    }

    const url = new URL(request.url);
    const raw = url.searchParams.get('raw');
    const data = await getFileFromRepo({
      env,
      query: {
        owner: url.searchParams.get('owner') || '',
        repo: url.searchParams.get('repo') || '',
        branch: url.searchParams.get('branch') || '',
        path: url.searchParams.get('path') || '',
        raw: raw === 'true',
      },
    });

    if (raw === 'true') {
      return new Response(data, {
        status: 200,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      });
    }

    return json(data);
  } catch (error) {
    const status = /not allowed|mismatch/i.test(error.message) ? 403 : 400;
    return json({ error: 'BAD_REQUEST', message: error.message }, status);
  }
}
