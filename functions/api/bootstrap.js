import {
  getAccessContext,
  getModePolicy,
} from '../lib/access-auth';
import { jsonResponse, respondWithMappedError } from '../lib/api-errors';

export async function onRequestGet({ request, env }) {
  try {
    const access = await getAccessContext(request, env);
    const policy = getModePolicy(access, env);

    return jsonResponse({
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
    return respondWithMappedError(error);
  }
}
