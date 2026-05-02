import {
  getAccessContext,
  getModePolicy,
} from '../lib/access-auth';

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

export async function onRequestGet({ request, env }) {
  try {
    const access = await getAccessContext(request, env);
    const policy = getModePolicy(access, env);

    return json({
      auth: {
        accessEnabled: access.accessEnabled,
        email: access.email || undefined,
        isAdmin: access.isAdmin,
      },
      modes: policy.modes,
      allowedModes: policy.allowedModes,
      defaultMode: policy.defaultMode,
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

