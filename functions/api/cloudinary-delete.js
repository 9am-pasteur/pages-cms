import { jsonResponse, respondWithMappedError } from '../lib/api-errors';
import { cloudinaryApiRequest } from '../lib/cloudinary';

export async function onRequestPost({ request, env }) {
  try {
    const allowDelete = String(env.CLOUDINARY_ALLOW_DELETE || 'true').trim().toLowerCase() !== 'false';
    if (!allowDelete) {
      return jsonResponse({
        error: 'CLOUDINARY_DELETE_DISABLED',
        message: 'Cloudinary delete is disabled by configuration.',
        check: ['CLOUDINARY_ALLOW_DELETE'],
      }, 403);
    }

    const body = await request.json().catch(() => ({}));
    const publicId = String(body?.public_id || '').trim();
    const type = String(body?.type || 'upload').trim();
    if (!publicId) {
      throw new Error('public_id is required');
    }

    const path = `/resources/image/${encodeURIComponent(type)}`;
    const data = await cloudinaryApiRequest(env, path, {
      method: 'DELETE',
      query: {
        'public_ids[]': publicId,
      },
    });

    return jsonResponse({
      ok: true,
      deleted: data?.deleted || null,
      partial: !!data?.partial,
      rate_limit_allowed: data?.rate_limit_allowed,
      rate_limit_remaining: data?.rate_limit_remaining,
      rate_limit_reset_at: data?.rate_limit_reset_at,
    });
  } catch (error) {
    return respondWithMappedError(error);
  }
}
