const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

const errorBody = ({ code, message, hint, check }) => ({
  error: code,
  message,
  ...(hint ? { hint } : {}),
  ...(check ? { check } : {}),
});

const mapStatusFromGithubError = (message) => {
  const match = String(message || '').match(/:\s(\d{3})\s/);
  if (!match) return 502;
  const status = Number(match[1]);
  if (Number.isNaN(status)) return 502;
  return status;
};

export const toHttpError = (error) => {
  const message = String(error?.message || 'Unexpected server error');

  if (/Path is not allowed/i.test(message)) {
    return {
      status: 403,
      body: errorBody({
        code: 'PATH_NOT_ALLOWED',
        message: 'This path is not writable in proxy mode.',
        hint: 'Only content paths are writable for non-admin proxy users.',
        check: ['CMS_PROXY_ALLOWED_PATHS', 'CMS_PROXY_DENIED_PATHS'],
      }),
    };
  }

  if (/Missing Access JWT|JWT|Access JWT|Malformed JWT|Unsupported JWT alg|Invalid JWT signature|No verification key found|Failed to fetch access certs|Missing email claim/i.test(message)) {
    return {
      status: 401,
      body: errorBody({
        code: 'ACCESS_JWT_INVALID',
        message: message,
        hint: 'Cloudflare Access token validation failed.',
        check: ['CLOUDFLARE_ACCESS_TEAM_DOMAIN', 'CLOUDFLARE_ACCESS_AUD', 'CLOUDFLARE_ACCESS_ISSUER'],
      }),
    };
  }

  if (/User denied/i.test(message)) {
    return {
      status: 403,
      body: errorBody({
        code: 'ACCESS_USER_DENIED',
        message: 'User is explicitly denied.',
        check: ['CMS_DENY_USERS'],
      }),
    };
  }

  if (/Missing proxy repository configuration|Missing env: GITHUB_REPO_/i.test(message)) {
    return {
      status: 500,
      body: errorBody({
        code: 'PROXY_REPO_NOT_CONFIGURED',
        message: message,
        hint: 'Proxy repository target is not fully configured.',
        check: ['GITHUB_REPO_OWNER', 'GITHUB_REPO_NAME', 'GITHUB_BRANCH'],
      }),
    };
  }

  if (/Missing env: GITHUB_APP_/i.test(message)) {
    return {
      status: 500,
      body: errorBody({
        code: 'GITHUB_APP_NOT_CONFIGURED',
        message: message,
        hint: 'GitHub App credentials are missing.',
        check: ['GITHUB_APP_ID', 'GITHUB_APP_INSTALLATION_ID', 'GITHUB_APP_PRIVATE_KEY'],
      }),
    };
  }

  if (/Failed to create installation token/i.test(message)) {
    return {
      status: 502,
      body: errorBody({
        code: 'GITHUB_APP_CONNECTION_FAILED',
        message: 'Failed to obtain installation token from GitHub App.',
        hint: 'Check GitHub App installation, private key, and repository access.',
        check: ['GITHUB_APP_ID', 'GITHUB_APP_INSTALLATION_ID', 'GITHUB_APP_PRIVATE_KEY'],
      }),
    };
  }

  if (/Resource not accessible by integration/i.test(message)) {
    return {
      status: 403,
      body: errorBody({
        code: 'GITHUB_APP_PERMISSION_DENIED',
        message: 'GitHub App is connected but does not have required repository permissions.',
        hint: 'Grant required repository permissions and ensure the app is installed on the target repo.',
      }),
    };
  }

  if (/GitHub API failed/i.test(message)) {
    const status = mapStatusFromGithubError(message);
    if (status === 404) {
      return {
        status: 404,
        body: errorBody({
          code: 'NOT_FOUND',
          message: 'Requested file or path was not found in the repository.',
        }),
      };
    }
    return {
      status: status >= 400 && status < 600 ? status : 502,
      body: errorBody({
        code: 'GITHUB_API_ERROR',
        message: 'GitHub API request failed.',
      }),
    };
  }

  if (/owner mismatch|repo mismatch/i.test(message)) {
    return {
      status: 403,
      body: errorBody({
        code: 'REPOSITORY_MISMATCH',
        message: 'Requested repository does not match configured proxy target.',
        check: ['GITHUB_REPO_OWNER', 'GITHUB_REPO_NAME'],
      }),
    };
  }

  if (/sha is required/i.test(message)) {
    return {
      status: 400,
      body: errorBody({
        code: 'MISSING_SHA',
        message: 'Delete operation requires sha.',
      }),
    };
  }

  return {
    status: 500,
    body: errorBody({
      code: 'INTERNAL_ERROR',
      message,
    }),
  };
};

export const respondWithMappedError = (error) => {
  const mapped = toHttpError(error);
  return json(mapped.body, mapped.status);
};

export const jsonResponse = json;
