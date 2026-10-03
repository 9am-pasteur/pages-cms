const requireCloudinaryEnv = (env) => {
  const cloudName = env.CLOUDINARY_CLOUD_NAME || '';
  const apiKey = env.CLOUDINARY_API_KEY || '';
  const apiSecret = env.CLOUDINARY_API_SECRET || '';
  if (!cloudName || !apiKey || !apiSecret) {
    throw new Error('Missing Cloudinary credentials: CLOUDINARY_CLOUD_NAME/CLOUDINARY_API_KEY/CLOUDINARY_API_SECRET');
  }
  return { cloudName, apiKey, apiSecret };
};

const sha1Hex = async (str) => {
  const data = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
};

const sha1Bytes = async (str) => {
  const data = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  return new Uint8Array(hashBuffer);
};

const toBase64Url = (bytes) => {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};

const buildApiAuthHeader = (apiKey, apiSecret) => {
  const basic = btoa(`${apiKey}:${apiSecret}`);
  return `Basic ${basic}`;
};

const cloudinaryApiRequest = async (env, path, { method = 'GET', query = null, json = null } = {}) => {
  const { cloudName, apiKey, apiSecret } = requireCloudinaryEnv(env);
  const url = new URL(`https://api.cloudinary.com/v1_1/${cloudName}${path}`);
  if (query && typeof query === 'object') {
    Object.entries(query).forEach(([key, value]) => {
      if (value === undefined || value === null || value === '') return;
      url.searchParams.set(key, String(value));
    });
  }
  const headers = {
    Authorization: buildApiAuthHeader(apiKey, apiSecret),
    Accept: 'application/json',
    'User-Agent': 'pages-cms-cloudinary/1.0',
  };
  const init = { method, headers };
  if (json !== null) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(json);
  }

  const response = await fetch(url.toString(), init);
  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (!response.ok) {
    const message = data?.error?.message || data?.message || `Cloudinary API failed: ${response.status}`;
    throw new Error(message);
  }

  return data;
};

const buildUploadSignature = async (apiSecret, params) => {
  const toSign = Object.entries(params)
    .filter(([, value]) => value !== undefined && value !== null && value !== '')
    .map(([key, value]) => [key, Array.isArray(value) ? value.join(',') : String(value)])
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join('&');
  return sha1Hex(`${toSign}${apiSecret}`);
};

const buildDeliverySignature = async (apiSecret, toSign) => {
  const digest = await sha1Bytes(`${toSign}${apiSecret}`);
  return toBase64Url(digest).slice(0, 8);
};

const normalizedTransform = ({ width, format = 'auto', quality = 'auto', extra = '' } = {}) => {
  const parts = [];
  if (quality) parts.push(`q_${quality}`);
  if (format) parts.push(`f_${format}`);
  if (width) parts.push(`w_${Number(width)}`);
  if (extra) parts.push(String(extra));
  return parts.join(',');
};

const normalizeCloudinaryType = (type) => {
  const t = String(type || '').trim();
  return t || 'upload';
};

const encodeRFC3986URIComponent = (str) => encodeURIComponent(str).replace(
  /[!'()*]/g,
  (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`
);

const encodeCloudinaryPublicIdPath = (publicId) => String(publicId || '')
  .split('/')
  .map((segment) => encodeRFC3986URIComponent(segment).replace(/~/g, '%7E'))
  .join('/');

const buildCloudinaryDeliveryPath = ({ type = 'upload', transform, publicId, version = null }) => {
  const v = Number(version);
  const versionPart = Number.isFinite(v) && v > 0 ? `/v${Math.trunc(v)}` : '';
  const encodedPublicId = encodeCloudinaryPublicIdPath(publicId);
  return `image/${normalizeCloudinaryType(type)}/${transform}${versionPart}/${encodedPublicId}`;
};

const buildCloudinarySignatureTarget = ({ transform, publicId, version = null }) => {
  const v = Number(version);
  const versionPart = Number.isFinite(v) && v > 0 ? `v${Math.trunc(v)}/` : '';
  const encodedPublicId = encodeCloudinaryPublicIdPath(publicId);
  return `${transform}/${versionPart}${encodedPublicId}`;
};

const buildCloudinaryDeliveryUrl = async ({
  cloudName,
  apiSecret,
  type = 'upload',
  transform,
  publicId,
  version = null,
  signed = false,
}) => {
  const path = buildCloudinaryDeliveryPath({ type, transform, publicId, version });
  if (!signed) {
    return `https://res.cloudinary.com/${cloudName}/${path}`;
  }
  const toSign = buildCloudinarySignatureTarget({ transform, publicId, version });
  const sig = await buildDeliverySignature(apiSecret, toSign);
  return `https://res.cloudinary.com/${cloudName}/image/${normalizeCloudinaryType(type)}/s--${sig}--/${toSign}`;
};

export {
  requireCloudinaryEnv,
  sha1Hex,
  cloudinaryApiRequest,
  buildUploadSignature,
  buildDeliverySignature,
  normalizedTransform,
  normalizeCloudinaryType,
  encodeCloudinaryPublicIdPath,
  buildCloudinaryDeliveryPath,
  buildCloudinarySignatureTarget,
  buildCloudinaryDeliveryUrl,
};
