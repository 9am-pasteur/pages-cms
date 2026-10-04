import { jsonResponse, respondWithMappedError } from '../lib/api-errors';
import {
  cloudinaryApiRequest,
  requireCloudinaryEnv,
  buildCloudinaryDeliveryUrl,
  extractDeliveryPublicIdFromSecureUrl,
} from '../lib/cloudinary';

const toNumberInRange = (value, fallback, min, max) => {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(n)));
};

const parseTypes = (value) => String(value || '')
  .split(',')
  .map((v) => v.trim())
  .filter(Boolean);

const sanitizeFolder = (value) => String(value || '')
  .trim()
  .replace(/^\/+|\/+$/g, '');

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

const buildPreviewTransform = ({ width, height, crop, format }) => {
  const base = `c_${crop},h_${height},w_${width}`;
  const withPage = String(format || '').toLowerCase() === 'pdf'
    ? `${base},pg_1`
    : base;
  // Cloudinary console style: base transform / f_auto / q_auto
  return `${withPage}/f_auto/q_auto`;
};

export async function onRequestGet({ request, env }) {
  try {
    const url = new URL(request.url);
    const maxResults = toNumberInRange(url.searchParams.get('max_results'), 30, 1, 100);
    const nextCursor = url.searchParams.get('next_cursor') || '';
    const q = (url.searchParams.get('q') || '').trim();
    const explicitTypes = parseTypes(url.searchParams.get('types'));
    const fallbackTypes = parseTypes(env.CLOUDINARY_ASSET_TYPES || 'upload');
    const types = explicitTypes.length > 0 ? explicitTypes : fallbackTypes;
    const folder = sanitizeFolder(url.searchParams.get('folder') || env.CLOUDINARY_ASSET_FOLDER || '');
    const typeExpr = buildTypeExpression(types);
    const extraExpr = q ? `(${q})` : '';
    const expressionParts = ['resource_type=image'];
    if (typeExpr) expressionParts.push(typeExpr);
    if (folder) expressionParts.push(`public_id=${folder}/*`);
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
    const { cloudName, apiSecret } = requireCloudinaryEnv(env);
    const previewSignedByDefault = String(env.CLOUDINARY_DELIVERY_SIGNED || '').toLowerCase() === 'true';
    const previewWidth = toNumberInRange(env.CLOUDINARY_PREVIEW_WIDTH || 240, 240, 40, 2048);
    const previewHeight = toNumberInRange(env.CLOUDINARY_PREVIEW_HEIGHT || 140, 140, 40, 2048);
    const previewFit = String(env.CLOUDINARY_PREVIEW_CROP || 'fill').trim() || 'fill';

    const mapped = await Promise.all(uniqueByAssetId(resources).map(async (asset) => {
      const type = String(asset?.type || 'upload');
      const publicId = String(asset?.public_id || '');
      // Prefer secure_url-derived delivery id to match Cloudinary's own tail representation.
      const deliveryPublicId = extractDeliveryPublicIdFromSecureUrl(asset?.secure_url);
      const format = String(asset?.format || '').toLowerCase();
      const transform = buildPreviewTransform({
        width: previewWidth,
        height: previewHeight,
        crop: previewFit,
        format,
      });
      const signed = previewSignedByDefault;
      const preview_url = await buildCloudinaryDeliveryUrl({
        cloudName,
        apiSecret,
        type,
        transform,
        publicId,
        deliveryPublicId,
        version: null,
        signed,
      });
      return {
        asset_id: asset.asset_id,
        public_id: asset.public_id,
        secure_url: asset.secure_url,
        original_url: asset.secure_url,
        preview_url,
        width: asset.width,
        height: asset.height,
        format: asset.format,
        type: asset.type,
        bytes: asset.bytes,
        created_at: asset.created_at,
        context: asset.context || null,
      };
    }));

    return jsonResponse({
      resources: mapped,
      next_cursor: data?.next_cursor || null,
    });
  } catch (error) {
    return respondWithMappedError(error);
  }
}
