// Basic auth middleware for Cloudflare Pages Functions (no Node.js built-ins).
import { isAccessJwtValid } from './lib/access-auth';

const encoder = new TextEncoder();

/**
 * Protect against timing attacks by safely comparing values using `timingSafeEqual`.
 * Refer to https://developers.cloudflare.com/workers/runtime-apis/web-crypto/#timingsafeequal for more details
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function timingSafeEqual(a, b) {
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);

  if (aBytes.byteLength !== bBytes.byteLength) {
    // Strings must be the same length in order to compare
    // with crypto.subtle.timingSafeEqual
    return false;
  }

  return crypto.subtle.timingSafeEqual(aBytes, bBytes);
}

const errorHandler = async ({ next }) => {
  try {
    return await next();
  } catch (err) {
    return new Response(`${err.message}\n${err.stack}`, { status: 500 });
  }
};

const guardByBasicAuth = async ({ request, next, env }) => {
  const modeRaw = String(env.BASIC_AUTH || '').trim().toLowerCase();
  const basicUser = env.BASIC_USERNAME || '';
  const basicPass = env.BASIC_PASSWORD || '';
  const basicEnabled = modeRaw !== '' && modeRaw !== 'false';

  if (!basicEnabled) {
    return await next();
  }

  // Safe default: if Basic auth is enabled but credentials are incomplete, deny access.
  if (!basicUser || !basicPass) {
    return new Response(
      'Basic auth is enabled but BASIC_USERNAME/BASIC_PASSWORD is not fully configured.',
      {
        status: 401,
        headers: {
          'WWW-Authenticate': 'Basic realm="Input username and password"',
        },
      }
    );
  }

  if (modeRaw === 'when_no_access') {
    // If request already has a valid Cloudflare Access JWT, skip Basic auth.
    // If Access is not configured or JWT is invalid/missing, fallback to Basic auth (safe side).
    if (env.CLOUDFLARE_ACCESS_TEAM_DOMAIN) {
      const validAccess = await isAccessJwtValid(request, env);
      if (validAccess) {
        return await next();
      }
    }
  }

  // Check header
  if (!request.headers.has('Authorization')) {
    return new Response(
      'You need to login.',
      {
        status: 401,
        headers: {
          // Prompts the user for credentials.
          'WWW-Authenticate': 'Basic realm="Input username and password"',
        },
      });
  }
  // Decode header value
  const [scheme, encoded] = request.headers.get('Authorization').split(' ');
  if (!encoded || scheme !== 'Basic') {
    return new Response(
      'Malformed authorization header.',
      {
        status: 400,
      },
    );
  }
  // Decode base64 without Node's Buffer (Pages/Workers environment)
  const credentials = atob(encoded);
  const index = credentials.indexOf(':');
  // eslint-disable-next-line no-control-regex
  if (index === -1 || /[\0-\x1F\x7F]/.test(credentials)) {
    return new Response(
      'Invalid authorization value.',
      {
        status: 400,
      },
    );
  }

  const username = credentials.substring(0, index);
  const password = credentials.substring(index + 1);
  if (
    !timingSafeEqual(basicUser, username) ||
    !timingSafeEqual(basicPass, password)
  ) {
    return new Response(
      'Invalid username or password.',
      {
        status: 401,
        headers: {
          // Prompts the user for credentials.
          'WWW-Authenticate': 'Basic realm="Input username and password"',
        },
      },
    );
  }
  return await next();
};

export const onRequest = [errorHandler, guardByBasicAuth];
