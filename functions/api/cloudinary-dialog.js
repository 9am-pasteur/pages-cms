export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const target = env.CLOUDINARY_DIALOG_URL;

  // Case 1: Proxy to external dialog if URL is configured
  if (target) {
    try {
      const upstream = await fetch(target, {
        method: request.method,
        headers: request.headers,
        body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
        redirect: 'follow',
      });
      const headers = new Headers(upstream.headers);
      headers.delete('content-security-policy');
      headers.delete('content-length');
      headers.set('access-control-allow-origin', url.origin);
      return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers });
    } catch (e) {
      return new Response('Upstream fetch failed', { status: 502 });
    }
  }

  // Case 2: Serve built-in Media Library dialog if API key is present
  if (env.CLOUDINARY_API_KEY) {
    const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Cloudinary Media Library</title>
  <style>
    html, body { margin: 0; height: 100%; font-family: sans-serif; }
    #status { margin: 8px; color: #555; font-size: 13px; position: absolute; top: 0; left: 0; }
    #ml-container { position: absolute; inset: 0; }
  </style>
  <script src="https://media-library.cloudinary.com/global/all.js"></script>
</head>
<body>
  <div id="status">Loading token…</div>
  <div id="ml-container"></div>
  <script>
    const statusEl = document.getElementById('status');
    const container = document.getElementById('ml-container');
    let cfg = null;

    fetch('/api/cloudinary-ml-token')
      .then(r => {
        if (!r.ok) throw new Error('Token request failed: ' + r.status);
        return r.json();
      })
      .then(data => {
        cfg = data;
        statusEl.textContent = 'Opening Media Library…';
        openML();
      })
      .catch(err => {
        statusEl.textContent = err.message;
      });

    function openML() {
      if (!cfg) return;
      const ml = cloudinary.openMediaLibrary({
        cloud_name: cfg.cloud_name,
        api_key: cfg.api_key,
        username: cfg.username || '',
        insert_caption: 'Insert',
        secure: true,
        default_transformations: [],
        signature: cfg.signature,
        timestamp: cfg.timestamp,
        remove_header: true,
        inline_container: '#ml-container',
      },{
        insertHandler: function(data) {
          if (!data || !data.assets || !data.assets.length) return;
          const asset = data.assets[0];
          const url = asset.secure_url || asset.url;
          const alt = asset.public_id || '';
          const html = '<img src=\"' + url + '\" alt=\"' + alt + '\" />';
          try {
            if (window.parent && window.parent.CKEDITOR) {
              const dlg = window.parent.CKEDITOR.dialog.getCurrent && window.parent.CKEDITOR.dialog.getCurrent();
              const editor = dlg && dlg.getParentEditor ? dlg.getParentEditor() : null;
              if (editor && editor.insertHtml) {
                editor.insertHtml(html);
                dlg && dlg.hide && dlg.hide();
                return;
              }
            }
          } catch(e){}
          window.parent?.postMessage({ type: 'cloudinary-insert', html }, '*');
        }
      });
      ml.show();
    }
  </script>
</body>
</html>`;
    return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
  }

  // Fallback
  return new Response('Cloudinary dialog not configured', { status: 500 });
}
