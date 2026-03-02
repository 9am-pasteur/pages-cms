// /js/ckeditor/plugins/cloudinary/plugin.js
CKEDITOR.plugins.add('cloudinary', {
  // アイコンファイルを用意しない場合は icons は省略可能。button 定義側で icon パスを指定します。
  init: function(editor) {
    // コマンドとボタン
    editor.addCommand('openCloudinaryDialog', new CKEDITOR.dialogCommand('cloudinaryDialog'));
    editor.ui.addButton('Cloudinary', {
      label: 'Cloudinaryより画像挿入',
      command: 'openCloudinaryDialog',
      toolbar: 'insert',
      icon: '/js/cloudinary_web_favicon.webp' // 任意のアイコンパス
    });

    // ダイアログ定義（iframe で cloudinary_dialog.pl を表示）
    CKEDITOR.dialog.add('cloudinaryDialog', function(editor) {
      var dialogUrl = '/api/cloudinary-dialog';
      return {
        title: 'Cloudinary から画像を選択',
        minWidth: 860,
        minHeight: 380,
        contents: [
          {
            id: 'cloudinaryTab',
            label: 'Cloudinary',
            elements: [
              {
                type: 'html',
                id: 'cloudinaryIframe',
                html:
                  '<iframe ' +
                  '  id="cloudinary_iframe" ' +
                  '  src="' + dialogUrl + '" ' +
                  '  style="width:100%; height:100%; min-height:360px; border:0;"' +
                  '></iframe>'
              }
            ]
          }
        ],
        // OK は独自ダイアログ(CLOUDINARY_DIALOG_URL)向けに残す。MLWの場合は insertIt が無ければ何もしない。
        buttons: [ CKEDITOR.dialog.okButton, CKEDITOR.dialog.cancelButton ],
        onOk: function() {
          try {
            var iframe = document.getElementById('cloudinary_iframe');
            if (iframe && iframe.contentWindow && typeof iframe.contentWindow.insertIt === 'function') {
              iframe.contentWindow.insertIt();
            }
          } catch (e) {
            // ignore
          }
        },
        onShow: function() {
          var dialog = this;
          var resizeAll = function() {
            adjustSizeToViewport(dialog);
            resizeIframe(dialog);
          };
          resizeAll();
          if (!dialog._boundResize) {
            dialog._boundResize = function() { resizeAll(); };
            CKEDITOR.document.getWindow().on('resize', dialog._boundResize);
          }
        },
        onHide: function() {
          if (this._boundResize) {
            CKEDITOR.document.getWindow().removeListener('resize', this._boundResize);
            this._boundResize = null;
          }
        },
      };
    });
  }
});

function adjustSizeToViewport(dialog) {
  var vp = CKEDITOR.document.getWindow().getViewPaneSize();
  var targetHeight = Math.max(380, Math.min(860, vp.height - 100));
  var targetWidth = Math.max(860, Math.min(1300, vp.width - 80));
  dialog.resize(targetWidth, targetHeight);
}

function resizeIframe(dialog) {
  var el = CKEDITOR.document.getById('cloudinary_iframe');
  if (!el) return;
  var vp = CKEDITOR.document.getWindow().getViewPaneSize();
  var h = Math.max(410, Math.min(900, vp.height - 110)); // 余白を110pxに緩和して高さを確保
  el.setStyle('height', h + 'px');
}
