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

const buildTypeExpression = (types) => {
  if (!Array.isArray(types) || types.length === 0) return '';
  const normalized = types
    .map((t) => String(t || '').trim())
    .filter(Boolean)
    .map((t) => `type=${t}`);
  if (normalized.length === 0) return '';
  if (normalized.length === 1) return normalized[0];
  return `(${normalized.join(' OR ')})`;
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
    const typeExpr = buildTypeExpression(types);
    const extraExpr = q ? `(${q})` : '';
    const expressionParts = ['resource_type=image'];
    if (typeExpr) expressionParts.push(typeExpr);
    if (extraExpr) expressionParts.push(extraExpr);
    const expression = expressionParts.join(' AND ');

    const data = await cloudinaryApiRequest(env, '/resources/search', {
      method: 'POST',
      json: {
        // q は expression として解釈。例: public_id="foo*" / tags=mytag
        expression,
        sort_by: [{ created_at: 'desc' }],
        max_results: maxResults,
        ...(nextCursor ? { next_cursor: nextCursor } : {}),
      },
    });

    const resources = Array.isArray(data?.resources) ? data.resources : [];
    return jsonResponse({
      resources: uniqueByAssetId(resources).map((asset) => ({
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
