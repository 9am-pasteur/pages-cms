import { jsonResponse, respondWithMappedError } from '../lib/api-errors';
import {
  requireCloudinaryEnv,
  normalizedTransform,
  buildCloudinaryDeliveryUrl,
} from '../lib/cloudinary';

const parseWidths = (value) => {
  if (Array.isArray(value)) {
    return value.map((v) => Number(v)).filter((v) => Number.isFinite(v) && v > 0);
  }
  return String(value || '')
    .split(',')
    .map((v) => Number(v.trim()))
    .filter((v) => Number.isFinite(v) && v > 0);
};

export async function onRequestPost({ request, env }) {
  try {
    const { cloudName, apiSecret } = requireCloudinaryEnv(env);
    const body = await request.json().catch(() => ({}));
    const publicId = String(body?.public_id || '').trim();
    if (!publicId) {
      return jsonResponse({ error: 'BAD_REQUEST', message: 'public_id is required' }, 400);
    }
    const widths = parseWidths(body?.widths);
    if (widths.length === 0) {
      return jsonResponse({ error: 'BAD_REQUEST', message: 'widths is required' }, 400);
    }

    const quality = body?.quality || 'auto';
    const format = body?.format || 'auto';
    const extra = body?.transform || '';
    const signed = body?.signed === true || String(env.CLOUDINARY_DELIVERY_SIGNED || '').toLowerCase() === 'true';

    const srcWidth = Number(body?.srcWidth);
    const fallbackWidth = Number.isFinite(srcWidth) && srcWidth > 0 ? srcWidth : widths[0];
    const type = String(body?.type || 'upload');
    const build = async (width) => {
      const transform = normalizedTransform({ width, quality, format, extra });
      return buildCloudinaryDeliveryUrl({
        cloudName,
        apiSecret,
        type,
        transform,
        publicId,
        signed,
      });
    };

    const src = await build(fallbackWidth);
    const srcsetEntries = [];
    for (const width of widths) {
      // eslint-disable-next-line no-await-in-loop
      const url = await build(width);
      srcsetEntries.push(`${url} ${width}w`);
    }

    return jsonResponse({
      src,
      srcset: srcsetEntries.join(', '),
      signed,
      widths,
      srcWidth: fallbackWidth,
    });
  } catch (error) {
    return respondWithMappedError(error);
  }
}
