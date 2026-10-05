const renderMlWidget = () => `<!doctype html>
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

const renderCustomDialog = ({ request, env }) => {
  const url = new URL(request.url);
  const templateDir = (env.CLOUDINARY_TEMPLATE_DIR || 'src/img-template').replace(/^\/+|\/+$/g, '');
  const assetFolder = (env.CLOUDINARY_ASSET_FOLDER || '').replace(/^\/+|\/+$/g, '');
  const defaultSrcsetWidths = env.CLOUDINARY_TEMPLATE_DEFAULT_SRCSET_WIDTHS || '300,600,900,1500';
  const defaultTransform = env.CLOUDINARY_TEMPLATE_DEFAULT_TRANSFORM || '';
  const provider = JSON.stringify(url.searchParams.get('provider') || '');
  const owner = JSON.stringify(url.searchParams.get('owner') || '');
  const repo = JSON.stringify(url.searchParams.get('repo') || '');
  const branch = JSON.stringify(url.searchParams.get('branch') || '');
  const templateDirJson = JSON.stringify(templateDir);
  const defaultSrcsetWidthsJson = JSON.stringify(defaultSrcsetWidths);
  const defaultTransformJson = JSON.stringify(defaultTransform);
  const assetFolderJson = JSON.stringify(assetFolder);
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Cloudinary Custom Dialog</title>
  <style>
    :root { color-scheme: light dark; }
    html, body { margin: 0; height: 100%; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
    .app { display: grid; grid-template-rows: auto 1fr auto; height: 100%; }
    .toolbar { display:flex; gap:8px; padding:10px; border-bottom:1px solid #ddd; align-items:center; }
    .toolbar input[type="text"] { flex:1; padding:8px 10px; border-radius:8px; border:1px solid #ccc; }
    .toolbar button { padding:8px 10px; border:1px solid #ccc; border-radius:8px; background:#fff; cursor:pointer; }
    .body { display:grid; grid-template-columns: 2fr 1fr; min-height:0; }
    .assets { overflow:auto; padding:10px; border-right:1px solid #ddd; }
    .assets-status { margin-bottom:8px; font-size:12px; color:#b91c1c; white-space:pre-wrap; }
    .asset-grid { display:grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap:10px; }
    .asset { border:1px solid #ddd; border-radius:8px; overflow:hidden; cursor:pointer; background:#fff; }
    .asset.selected { outline: 2px solid #2563eb; }
    .asset img { width:100%; height:110px; object-fit:cover; display:block; background:#f6f6f6; }
    .asset .meta { padding:6px 8px; font-size:12px; color:#444; word-break:break-all; }
    .side { overflow:auto; padding:10px; }
    .side label { display:block; font-size:12px; color:#666; margin-bottom:4px; }
    .side select, .side textarea { width:100%; box-sizing:border-box; border:1px solid #ccc; border-radius:8px; padding:8px; }
    .side textarea { min-height:180px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; }
    .status { font-size:12px; color:#666; margin-top:8px; }
    .footer { padding:10px; border-top:1px solid #ddd; display:flex; justify-content:space-between; gap:10px; align-items:center; }
    .footer .right { display:flex; gap:8px; }
    .footer button { padding:8px 12px; border-radius:8px; border:1px solid #ccc; background:#fff; cursor:pointer; }
    .footer button.primary { border-color:#2563eb; background:#2563eb; color:#fff; }
    .muted { color:#888; font-size:12px; }
  </style>
</head>
<body>
  <div class="app">
    <div class="toolbar">
      <input id="q" type="text" placeholder="Search Cloudinary assets (expression)" />
      <button id="searchBtn" type="button">Search</button>
      <button id="uploadBtn" type="button">Upload</button>
      <input id="uploadInput" type="file" accept="image/*" style="display:none" />
    </div>
    <div class="body">
      <div class="assets">
        <div id="assetsStatus" class="assets-status"></div>
        <div id="assetGrid" class="asset-grid"></div>
        <div style="margin-top:10px"><button id="moreBtn" type="button">Load more</button></div>
      </div>
      <div class="side">
        <label for="templateSel">Template</label>
        <select id="templateSel"></select>
        <div class="status" id="templateInfo"></div>
        <div style="height:10px"></div>
        <label for="preview">Preview HTML</label>
        <textarea id="preview" readonly></textarea>
        <div class="status" id="status"></div>
      </div>
    </div>
    <div class="footer">
      <div class="muted" id="summary">No asset selected.</div>
      <div class="right">
        <button type="button" id="cancelBtn">Cancel</button>
        <button type="button" id="insertBtn" class="primary">Insert</button>
      </div>
    </div>
  </div>
  <script>
    const cfg = {
      provider: ${provider},
      owner: ${owner},
      repo: ${repo},
      branch: ${branch},
      templateDir: ${templateDirJson},
      assetFolder: ${assetFolderJson},
      defaultSrcsetWidths: ${defaultSrcsetWidthsJson},
      defaultTransform: ${defaultTransformJson},
    };

    const state = {
      q: '',
      nextCursor: null,
      assets: [],
      selectedAsset: null,
      templates: [],
      selectedTemplateIdx: -1,
      loadingAssets: false,
    };

    const els = {
      q: document.getElementById('q'),
      searchBtn: document.getElementById('searchBtn'),
      uploadBtn: document.getElementById('uploadBtn'),
      uploadInput: document.getElementById('uploadInput'),
      assetGrid: document.getElementById('assetGrid'),
      assetsStatus: document.getElementById('assetsStatus'),
      moreBtn: document.getElementById('moreBtn'),
      templateSel: document.getElementById('templateSel'),
      templateInfo: document.getElementById('templateInfo'),
      preview: document.getElementById('preview'),
      status: document.getElementById('status'),
      summary: document.getElementById('summary'),
      cancelBtn: document.getElementById('cancelBtn'),
      insertBtn: document.getElementById('insertBtn'),
    };

    const setStatus = (msg) => { els.status.textContent = msg || ''; };
    const setAssetsStatus = (msg) => { els.assetsStatus.textContent = msg || ''; };
    const parseWidths = (value) => String(value || '').split(',').map(v => Number(v.trim())).filter(v => Number.isFinite(v) && v > 0);
    const escapeHtml = (s) => String(s || '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<':'&lt;','>':'&gt;','"':'&quot;' }[c]));
    const readLocalToken = () => localStorage.getItem('token') || '';
    const normalizeFolder = (value) => String(value || '').trim().replace(/^\\/+|\\/+$/g, '');
    const stripExtension = (name) => {
      const s = String(name || '').trim();
      return s.replace(/\\.[^/.]+$/, '');
    };
    const sanitizePublicIdBase = (name) => {
      const raw = stripExtension(name)
        .normalize('NFKC')
        .replace(/\\s+/g, '-')
        .replace(/[^0-9A-Za-z._-]/g, '-')
        .replace(/-+/g, '-')
        .replace(/^-+|-+$/g, '')
        .replace(/^[._-]+|[._-]+$/g, '')
        .toLowerCase();
      return (raw || 'img').slice(0, 80);
    };
    const randomSuffix = (len = 4) => {
      const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
      let out = '';
      const arr = new Uint8Array(len);
      crypto.getRandomValues(arr);
      for (let i = 0; i < len; i += 1) out += chars[arr[i] % chars.length];
      return out;
    };
    const buildUploadPublicId = (fileName) => {
      const base = sanitizePublicIdBase(fileName);
      return base + '-' + randomSuffix(4);
    };
    const sanitizeContextValue = (value) => String(value || '')
      .replace(/\\|/g, '/')
      .replace(/=/g, '-')
      .trim();
    const buildUploadContext = (fileName) => {
      const original = String(fileName || '').trim();
      const alt = stripExtension(original);
      const pairs = [];
      if (original) pairs.push('original_filename=' + sanitizeContextValue(original));
      if (alt) pairs.push('alt=' + sanitizeContextValue(alt));
      return pairs.join('|');
    };

    const loadAssets = async (reset = true) => {
      if (state.loadingAssets) return;
      state.loadingAssets = true;
      try {
        setAssetsStatus('');
        if (reset) {
          state.nextCursor = null;
          state.assets = [];
          state.selectedAsset = null;
        }
        const qs = new URLSearchParams();
        if (state.q) qs.set('q', state.q);
        if (!reset && state.nextCursor) qs.set('next_cursor', state.nextCursor);
        qs.set('max_results', '40');
        const res = await fetch('/api/cloudinary-assets?' + qs.toString());
        const data = await res.json();
        if (!res.ok) throw new Error(data?.message || 'Failed to load assets');
        state.assets = state.assets.concat(Array.isArray(data.resources) ? data.resources : []);
        state.nextCursor = data.next_cursor || null;
        renderAssets();
        if (state.assets.length === 0) {
          setAssetsStatus('No assets found. Cloudinary asset list may be empty, or this API key may not have sufficient permissions.');
        } else {
          setAssetsStatus('');
        }
      } catch (e) {
        const message = e.message || 'Failed to load assets';
        const hint = /forbidden|denied|permission|not allowed|unauthorized|401|403/i.test(message)
          ? '\\nHint: API authorization failed (401/403 or equivalent). Check Cloudinary API key role/permissions.'
          : '';
        setAssetsStatus(message + hint);
        setStatus(message);
      } finally {
        state.loadingAssets = false;
        els.moreBtn.disabled = !state.nextCursor;
      }
    };

    const renderAssets = () => {
      els.assetGrid.innerHTML = '';
      for (const asset of state.assets) {
        const card = document.createElement('button');
        card.type = 'button';
        card.className = 'asset' + (state.selectedAsset && state.selectedAsset.asset_id === asset.asset_id ? ' selected' : '');
        var thumb = asset.preview_url || asset.secure_url;
        card.innerHTML = '<img src="' + escapeHtml(thumb) + '" alt="" /><div class="meta">' + escapeHtml(asset.public_id) + '</div>';
        card.addEventListener('click', () => {
          state.selectedAsset = asset;
          renderAssets();
          renderPreview();
        });
        els.assetGrid.appendChild(card);
      }
      els.summary.textContent = state.selectedAsset
        ? ('Selected: ' + state.selectedAsset.public_id)
        : 'No asset selected.';
    };

    const loadTemplates = async () => {
      if (!cfg.provider || !cfg.owner || !cfg.repo) {
        state.templates = [];
        renderTemplateSelect();
        return;
      }
      try {
        const qs = new URLSearchParams({
          provider: cfg.provider,
          owner: cfg.owner,
          repo: cfg.repo,
          branch: cfg.branch || '',
          dir: cfg.templateDir,
        });
        const headers = {};
        if (cfg.provider === 'github' || cfg.provider === 'gitlab') {
          const token = readLocalToken();
          if (token) headers.Authorization = 'Bearer ' + token;
        }
        const res = await fetch('/api/cloudinary-templates?' + qs.toString(), { headers });
        const data = await res.json();
        if (!res.ok) throw new Error(data?.message || 'Failed to load templates');
        state.templates = Array.isArray(data.templates) ? data.templates : [];
        state.selectedTemplateIdx = state.templates.length > 0 ? 0 : -1;
        renderTemplateSelect();
        renderPreview();
      } catch (e) {
        setStatus(e.message || 'Failed to load templates');
      }
    };

    const renderTemplateSelect = () => {
      els.templateSel.innerHTML = '';
      const none = document.createElement('option');
      none.value = '-1';
      none.textContent = '(Default <img>)';
      els.templateSel.appendChild(none);
      state.templates.forEach((t, idx) => {
        const opt = document.createElement('option');
        opt.value = String(idx);
        opt.textContent = t.no ? (t.no + ': ' + t.title) : t.title;
        els.templateSel.appendChild(opt);
      });
      els.templateSel.value = String(state.selectedTemplateIdx);
      els.templateInfo.textContent = state.templates.length > 0
        ? ('Loaded ' + state.templates.length + ' templates from ' + cfg.templateDir)
        : ('No templates in ' + cfg.templateDir + ' (default <img> is available)');
    };

    const getSelectedTemplate = () => {
      if (state.selectedTemplateIdx < 0) return null;
      return state.templates[state.selectedTemplateIdx] || null;
    };

    const getAssetAlt = (asset) => {
      const c = asset && asset.context ? asset.context : null;
      return c?.custom?.alt || c?.alt || asset?.public_id || '';
    };

    const getOriginalUrl = (asset) => asset?.original_url || asset?.secure_url || '';
    const buildDefaultHtml = (asset) => '<img src="' + asset.secure_url + '" alt="' + escapeHtml(getAssetAlt(asset)) + '" />';

    const buildTemplateHtml = async (asset, template) => {
      if (!template || !template.html) return buildDefaultHtml(asset);
      const widths = parseWidths(template.srcsetWidths || cfg.defaultSrcsetWidths);
      let src = asset.secure_url;
      let srcset = '';
      const originalUrl = getOriginalUrl(asset);
      if (widths.length > 0) {
        const res = await fetch('/api/cloudinary-delivery-urls', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            public_id: asset.public_id,
            widths,
            srcWidth: template.srcWidth || widths[0],
            transform: template.transform || cfg.defaultTransform || '',
            format: 'auto',
            quality: 'auto',
          }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data?.message || 'Failed to build delivery URLs');
        src = data.src || src;
        srcset = data.srcset || '';
      }
      return String(template.html)
        .replaceAll('\${src}', src)
        .replaceAll('\${srcset}', srcset)
        .replaceAll('\${alt}', getAssetAlt(asset))
        .replaceAll('\${public_id}', asset.public_id || '')
        .replaceAll('\${original_url}', originalUrl)
        .replaceAll('\${href}', originalUrl);
    };

    const renderPreview = async () => {
      if (!state.selectedAsset) {
        els.preview.value = '';
        return;
      }
      try {
        const t = getSelectedTemplate();
        const html = t ? await buildTemplateHtml(state.selectedAsset, t) : buildDefaultHtml(state.selectedAsset);
        els.preview.value = html;
      } catch (e) {
        setStatus(e.message || 'Failed to render preview');
      }
    };

    const insertToEditor = (html) => {
      try {
        if (window.parent && window.parent.CKEDITOR) {
          const dlg = window.parent.CKEDITOR.dialog.getCurrent && window.parent.CKEDITOR.dialog.getCurrent();
          const editor = dlg && dlg.getParentEditor ? dlg.getParentEditor() : null;
          if (editor && editor.insertHtml) {
            editor.insertHtml(html);
            dlg && dlg.hide && dlg.hide();
            return true;
          }
        }
      } catch (e) {}
      window.parent?.postMessage({ type: 'cloudinary-insert', html }, '*');
      return false;
    };

    const doInsert = async () => {
      if (!state.selectedAsset) {
        setStatus('Select an asset first.');
        return;
      }
      try {
        const t = getSelectedTemplate();
        const html = t ? await buildTemplateHtml(state.selectedAsset, t) : buildDefaultHtml(state.selectedAsset);
        insertToEditor(html);
      } catch (e) {
        setStatus(e.message || 'Insert failed');
      }
    };

    const doUpload = async (file) => {
      if (!file) return;
      try {
        setStatus('Preparing upload…');
        const publicId = buildUploadPublicId(file.name);
        const context = buildUploadContext(file.name);
        const folder = normalizeFolder(cfg.assetFolder);
        const signRes = await fetch('/api/cloudinary-upload-sign', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            public_id: publicId,
            ...(folder ? { folder } : {}),
            ...(context ? { context } : {}),
          }),
        });
        const sign = await signRes.json();
        if (!signRes.ok) throw new Error(sign?.message || 'Failed to sign upload');
        const fd = new FormData();
        fd.set('file', file);
        fd.set('api_key', sign.api_key);
        fd.set('timestamp', String(sign.timestamp));
        fd.set('signature', sign.signature);
        Object.entries(sign.params || {}).forEach(([k, v]) => {
          if (k === 'timestamp') return;
          if (v === undefined || v === null || v === '') return;
          fd.set(k, String(v));
        });
        const up = await fetch(sign.upload_url, { method: 'POST', body: fd });
        const upData = await up.json();
        if (!up.ok) throw new Error(upData?.error?.message || 'Upload failed');
        setStatus('Upload completed.');
        await loadAssets(true);
      } catch (e) {
        setStatus(e.message || 'Upload failed');
      }
    };

    window.insertIt = () => { doInsert(); };

    els.searchBtn.addEventListener('click', () => {
      state.q = els.q.value.trim();
      loadAssets(true);
    });
    els.q.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter') {
        state.q = els.q.value.trim();
        loadAssets(true);
      }
    });
    els.moreBtn.addEventListener('click', () => loadAssets(false));
    els.uploadBtn.addEventListener('click', () => els.uploadInput.click());
    els.uploadInput.addEventListener('change', () => {
      const f = els.uploadInput.files && els.uploadInput.files[0];
      doUpload(f);
      els.uploadInput.value = '';
    });
    els.templateSel.addEventListener('change', () => {
      state.selectedTemplateIdx = Number(els.templateSel.value);
      renderPreview();
    });
    els.cancelBtn.addEventListener('click', () => {
      try {
        const dlg = window.parent?.CKEDITOR?.dialog?.getCurrent?.();
        dlg && dlg.hide && dlg.hide();
      } catch(e){}
    });
    els.insertBtn.addEventListener('click', () => doInsert());

    loadAssets(true);
    loadTemplates();
  </script>
</body>
</html>`;
};

const modeFromEnv = (env) => {
  const explicit = String(env.CLOUDINARY_DIALOG_MODE || '').trim().toLowerCase();
  if (explicit === 'proxy' || explicit === 'mlw' || explicit === 'custom') {
    return explicit;
  }
  if (env.CLOUDINARY_DIALOG_URL) return 'proxy';
  if (env.CLOUDINARY_API_KEY) return 'custom';
  return '';
};

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const target = env.CLOUDINARY_DIALOG_URL;
  const mode = modeFromEnv(env);

  if (mode === 'proxy') {
    if (!target) return new Response('CLOUDINARY_DIALOG_URL is required when CLOUDINARY_DIALOG_MODE=proxy', { status: 500 });
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
    } catch {
      return new Response('Upstream fetch failed', { status: 502 });
    }
  }

  if (mode === 'mlw') {
    if (!env.CLOUDINARY_API_KEY) return new Response('Cloudinary credentials not configured', { status: 500 });
    return new Response(renderMlWidget(), { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
  }

  if (mode === 'custom') {
    if (!env.CLOUDINARY_API_KEY) return new Response('Cloudinary credentials not configured', { status: 500 });
    return new Response(renderCustomDialog({ request, env }), { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
  }

  return new Response('Cloudinary dialog not configured', { status: 500 });
}
