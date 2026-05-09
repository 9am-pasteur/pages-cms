import { jsonResponse } from '../lib/api-errors';

const isObject = (value) => value && typeof value === 'object' && !Array.isArray(value);

const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

const parseProviders = (env) => {
  const raw = String(env.CMS_TAG_SUGGEST_PROVIDERS || '').trim();
  if (!raw) return {};
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('CMS_TAG_SUGGEST_PROVIDERS must be valid JSON.');
  }
  if (!isObject(parsed)) {
    throw new Error('CMS_TAG_SUGGEST_PROVIDERS must be a JSON object.');
  }
  return parsed;
};

const normalizeItems = (data) => {
  const source = Array.isArray(data)
    ? data
    : (Array.isArray(data?.items)
      ? data.items
      : (Array.isArray(data?.candidates)
        ? data.candidates
        : (Array.isArray(data?.tags) ? data.tags : [])));

  return source
    .map((item) => {
      if (typeof item === 'string') {
        return { tag: item.trim(), description: '' };
      }
      if (!isObject(item)) return null;
      const tag = String(item.tag || item.value || item.name || item.label || '').trim();
      if (!tag) return null;
      const description = String(item.description || item.details || item.summary || '').trim();
      return { tag, description };
    })
    .filter(Boolean);
};

const fetchJsonWithTimeout = async (url, init, timeoutMs) => {
  const controller = new AbortController();
  const timerId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    return response;
  } finally {
    clearTimeout(timerId);
  }
};

export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json().catch(() => ({}));
    const providerId = String(body?.provider || '').trim();
    if (!providerId) {
      return jsonResponse({ error: 'BAD_REQUEST', message: 'provider is required' }, 400);
    }

    const providers = parseProviders(env);
    const provider = providers[providerId];
    if (!isObject(provider)) {
      return jsonResponse({ error: 'BAD_REQUEST', message: `Unknown provider: ${providerId}` }, 400);
    }

    const endpoint = String(provider.endpoint || '').trim();
    if (!endpoint) {
      return jsonResponse({ error: 'BAD_REQUEST', message: `Missing endpoint for provider: ${providerId}` }, 400);
    }
    const isHttp = endpoint.startsWith('https://') || endpoint.startsWith('http://');
    if (!isHttp) {
      return jsonResponse({ error: 'BAD_REQUEST', message: `Endpoint must be http(s): ${providerId}` }, 400);
    }

    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };

    if (isObject(provider.headers)) {
      for (const [key, value] of Object.entries(provider.headers)) {
        headers[key] = String(value);
      }
    }

    const apiKey = String(provider.apiKey || '').trim();
    if (apiKey) {
      const apiKeyHeader = String(provider.apiKeyHeader || 'x-api-key').trim();
      headers[apiKeyHeader] = apiKey;
    }

    const timeoutMs = clamp(Number(provider.timeoutMs) || 8000, 1000, 20000);
    const maxItems = clamp(Number(provider.maxItems) || 20, 1, 100);
    const payload = {
      query: String(body?.query || ''),
      tokens: Array.isArray(body?.tokens) ? body.tokens.map((token) => String(token)) : [],
      field: String(body?.field || ''),
      record: isObject(body?.record) ? body.record : {},
      ...(isObject(provider.payload) ? provider.payload : {}),
    };

    const upstream = await fetchJsonWithTimeout(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    }, timeoutMs);

    const responseText = await upstream.text();
    let upstreamJson;
    try {
      upstreamJson = responseText ? JSON.parse(responseText) : {};
    } catch {
      upstreamJson = { raw: responseText };
    }

    if (!upstream.ok) {
      return jsonResponse({
        error: 'UPSTREAM_ERROR',
        message: `Tag suggest upstream returned ${upstream.status}`,
      }, 502);
    }

    const items = normalizeItems(upstreamJson).slice(0, maxItems);
    return jsonResponse({ items }, 200);
  } catch (error) {
    return jsonResponse({
      error: 'INTERNAL_ERROR',
      message: String(error?.message || 'Unexpected server error'),
    }, 500);
  }
}
