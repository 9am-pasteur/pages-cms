import { jsonResponse, respondWithMappedError } from '../lib/api-errors';
import { requireCloudinaryEnv, buildUploadSignature } from '../lib/cloudinary';

const pickAllowed = (body, keys) => {
  const out = {};
  for (const key of keys) {
    if (body[key] !== undefined && body[key] !== null && body[key] !== '') {
      out[key] = body[key];
    }
  }
  return out;
};

export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json().catch(() => ({}));
    const { cloudName, apiKey, apiSecret } = requireCloudinaryEnv(env);
    const timestamp = Math.floor(Date.now() / 1000);
    const enforcedFolder = String(env.CLOUDINARY_ASSET_FOLDER || '').trim().replace(/^\/+|\/+$/g, '');
    const requested = pickAllowed(body || {}, [
      'folder',
      'public_id',
      'overwrite',
      'tags',
      'context',
      'eager',
      'invalidate',
      'upload_preset',
    ]);
    const params = {
      timestamp,
      ...requested,
      ...(enforcedFolder ? { folder: enforcedFolder } : {}),
    };
    const signature = await buildUploadSignature(apiSecret, params);

    return jsonResponse({
      cloud_name: cloudName,
      api_key: apiKey,
      timestamp,
      signature,
      params,
      upload_url: `https://api.cloudinary.com/v1_1/${cloudName}/image/upload`,
    });
  } catch (error) {
    return respondWithMappedError(error);
  }
}
