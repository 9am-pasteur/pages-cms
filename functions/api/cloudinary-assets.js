import { jsonResponse, respondWithMappedError } from '../lib/api-errors';
import { cloudinaryApiRequest } from '../lib/cloudinary';

const toNumberInRange = (value, fallback, min, max) => {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(n)));
};

const parseTypes = (value) => String(value || '')
  .split(',')
  .map((v) => v.trim())
  .filter(Boolean);

const uniqueByAssetId = (list) => {
  const seen = new Set();
  const out = [];
  for (const item of list) {
    const key = item?.asset_id || `${item?.public_id || ''}:${item?.version || ''}`;
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
};

export async function onRequestGet({ request, env }) {
  try {
    const url = new URL(request.url);
    const maxResults = toNumberInRange(url.searchParams.get('max_results'), 30, 1, 100);
    const nextCursor = url.searchParams.get('next_cursor') || '';
    const q = (url.searchParams.get('q') || '').trim();
    const explicitTypes = parseTypes(url.searchParams.get('types'));
    const fallbackTypes = parseTypes(env.CLOUDINARY_ASSET_TYPES || 'upload,private,authenticated');
    const types = explicitTypes.length > 0 ? explicitTypes : fallbackTypes;

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
      : await (async () => {
        const merged = [];
        let next = null;
        const tried = [];
        for (const type of types) {
          // next_cursor は type ごとに独立するので、通常は type 固定で使う想定。
          // 明示指定時のみ next_cursor を適用する。
          // eslint-disable-next-line no-await-in-loop
          const part = await cloudinaryApiRequest(env, `/resources/image/${encodeURIComponent(type)}`, {
            method: 'GET',
            query: {
              max_results: maxResults,
              ...(explicitTypes.length > 0 && nextCursor ? { next_cursor: nextCursor } : {}),
            },
          });
          tried.push(type);
          if (Array.isArray(part?.resources) && part.resources.length > 0) {
            merged.push(...part.resources);
            next = part?.next_cursor || null;
            // type を跨いだページングは扱いづらいため、最初にヒットした type を優先して返す。
            break;
          }
        }
        return { resources: uniqueByAssetId(merged), next_cursor: next, _triedTypes: tried };
      })();

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
      source_types: data?._triedTypes || (q ? ['search'] : types),
    });
  } catch (error) {
    return respondWithMappedError(error);
  }
}
