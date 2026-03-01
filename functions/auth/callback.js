// Pass-through: redirect back to SPA with original query params so the client handles code exchange.
export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const base = (env.BASE_URL || '').replace(/\/$/, '') || `${url.origin}`;
  const qs = url.search ? url.search : '';
  return Response.redirect(`${base}/${qs}`, 302);
}
