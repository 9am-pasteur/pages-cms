/**
 * Shows how to restrict access using the HTTP Basic schema.
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication
 * @see https://tools.ietf.org/html/rfc7617
 *
 */

import { Buffer } from "node:buffer";

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
  if (env.BASIC_AUTH !== 'true') {
    return await next();
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
  const credentials = Buffer.from(encoded, "base64").toString();
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
    !timingSafeEqual(env.BASIC_USERNAME, username) ||
    !timingSafeEqual(env.BASIC_PASSWORD, password)
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

