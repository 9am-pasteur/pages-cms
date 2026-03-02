// Returns a short-lived signature for Cloudinary Media Library Widget
export async function onRequest(context) {
  const { env } = context;
  const { CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET, CLOUDINARY_USERNAME } = env;
  if (!CLOUDINARY_CLOUD_NAME || !CLOUDINARY_API_KEY || !CLOUDINARY_API_SECRET) {
    return new Response('Cloudinary credentials not configured', { status: 500 });
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const paramsToSign = `timestamp=${timestamp}`;

  const signature = await sha1Hex(paramsToSign + CLOUDINARY_API_SECRET);

  return Response.json({
    cloud_name: CLOUDINARY_CLOUD_NAME,
    api_key: CLOUDINARY_API_KEY,
    username: CLOUDINARY_USERNAME || '',
    timestamp,
    signature,
  });
}

async function sha1Hex(str) {
  const data = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
