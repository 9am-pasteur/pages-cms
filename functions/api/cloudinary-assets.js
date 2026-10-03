import { jsonResponse, respondWithMappedError } from '../lib/api-errors';
import { cloudinaryApiRequest } from '../lib/cloudinary';

const toNumberInRange = (value, fallback, min, max) => {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(n)));
};

export async function onRequestGet({ request, env }) {
  try {
    const url = new URL(request.url);
    const maxResults = toNumberInRange(url.searchParams.get('max_results'), 30, 1, 100);
    const nextCursor = url.searchParams.get('next_cursor') || '';
    const q = (url.searchParams.get('q') || '').trim();

    const data = q
      ? await cloudinaryApiRequest(env, '/resources/search', {
        method: 'POST',
        json: {
          // Free-text search on public_id/context/tags.
          expression: `resource_type:image AND (${q})`,
          sort_by: [{ created_at: 'desc' }],
          max_results: maxResults,
          ...(nextCursor ? { next_cursor: nextCursor } : {}),
        },
      })
      : await cloudinaryApiRequest(env, '/resources/image', {
        method: 'GET',
        query: {
          type: 'upload',
          max_results: maxResults,
          ...(nextCursor ? { next_cursor: nextCursor } : {}),
        },
      });

    const resources = Array.isArray(data?.resources) ? data.resources : [];
    return jsonResponse({
      resources: resources.map((asset) => ({
        asset_id: asset.asset_id,
        public_id: asset.public_id,
        secure_url: asset.secure_url,
        width: asset.width,
        height: asset.height,
        format: asset.format,
        bytes: asset.bytes,
        created_at: asset.created_at,
        context: asset.context || null,
      })),
      next_cursor: data?.next_cursor || null,
    });
  } catch (error) {
    return respondWithMappedError(error);
  }
}
