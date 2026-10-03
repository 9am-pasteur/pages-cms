import { requireCloudinaryEnv, sha1Hex } from '../lib/cloudinary';

// Returns a short-lived signature for Cloudinary Media Library Widget
export async function onRequest(context) {
  const { env } = context;
  const { cloudName, apiKey, apiSecret } = requireCloudinaryEnv(env);
  const timestamp = Math.floor(Date.now() / 1000);
  const paramsToSign = `timestamp=${timestamp}`;

  const signature = await sha1Hex(paramsToSign + apiSecret);

  return Response.json({
    cloud_name: cloudName,
    api_key: apiKey,
    username: env.CLOUDINARY_USERNAME || '',
    timestamp,
    signature,
  });
}
