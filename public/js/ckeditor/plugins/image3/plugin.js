/*
 * Image3 plugin: extends image2 UX with explicit float controls.
 * - Keeps justify buttons for paragraph alignment.
 * - Adds image-specific float commands: left / none / right.
 * - Hides "center" option from image2 dialog.
 */
(function() {
  function getFocusedImageWidget(editor) {
    var w = editor.widgets && editor.widgets.focused;
    return (w && w.name === 'image') ? w : null;
  }

  function getClosestBlock(el) {
    if (!el) return null;
    var block = el.getAscendant(function(node) {
      return node && node.type === CKEDITOR.NODE_ELEMENT && (node.is('p') || node.is('div'));
    }, true);
    return block || null;
  }

  function addImageFloatCommand(editor, name, align) {
    editor.addCommand(name, {
      exec: function(ed) {
        var widget = getFocusedImageWidget(ed);
        if (!widget) return;
        widget.setData('align', align);
      },
      refresh: function(ed) {
        var widget = getFocusedImageWidget(ed);
        if (!widget) {
          this.setState(CKEDITOR.TRISTATE_DISABLED);
          return;
        }
        this.setState(widget.data.align === align ? CKEDITOR.TRISTATE_ON : CKEDITOR.TRISTATE_OFF);
      }
    });
  }

  function patchJustifyForParagraph(editor) {
    ['left', 'center', 'right'].forEach(function(dir) {
      var cmd = editor.getCommand('justify' + dir);
      if (!cmd) return;

      // Run before image2's command integrator.
      cmd.on('exec', function() {
        var widget = getFocusedImageWidget(editor);
        if (!widget) return;

        var block = getClosestBlock(widget.wrapper);
        if (!block) return;

        var sel = editor.getSelection();
        var range = editor.createRange();
        range.selectNodeContents(block);

        var focused = editor.widgets.focused;
        editor.widgets.focused = null;
        sel.selectRanges([range]);

        CKEDITOR.tools.setTimeout(function() {
          // Do not force re-focus widget; keep paragraph selection result.
          if (editor.widgets && editor.widgets.focused === null) {
            editor.widgets.focused = focused || null;
          }
        }, 0);
      }, null, null, 999);
    });
  }

  function removeCenterFromImage2Dialog() {
    CKEDITOR.on('dialogDefinition', function(evt) {
      if (evt.data.name !== 'image2') return;

      var def = evt.data.definition;
      var info = def.getContents('info');
      if (!info || !info.elements) return;

      var alignField = null;
      function walk(elements) {
        if (!elements || !elements.length || alignField) return;
        for (var i = 0; i < elements.length; i += 1) {
          var el = elements[i];
          if (el && el.id === 'align' && el.type === 'radio') {
            alignField = el;
            return;
          }
          if (el && el.children) walk(el.children);
        }
      }

      walk(info.elements);
      if (!alignField || !Array.isArray(alignField.items)) return;

      alignField.items = alignField.items.filter(function(item) {
        return item && item[1] !== 'center';
      });

      var originalSetup = alignField.setup;
      alignField.setup = function(widget) {
        if (originalSetup) originalSetup.call(this, widget);
        if (this.getValue && this.getValue() === 'center') {
          this.setValue('none');
        }
      };
    });
  }

  CKEDITOR.plugins.add('image3', {
    requires: 'image2,justify',
    icons: 'imagefloatleft,imagefloatnone,imagefloatright',
    hidpi: false,
    init: function(editor) {
      addImageFloatCommand(editor, 'image3FloatLeft', 'left');
      addImageFloatCommand(editor, 'image3FloatNone', 'none');
      addImageFloatCommand(editor, 'image3FloatRight', 'right');

      if (editor.ui && editor.ui.addButton) {
        editor.ui.addButton('Image3FloatLeft', {
          label: '画像: 左回り込み',
          command: 'image3FloatLeft',
          toolbar: 'align,15',
          icon: this.path + 'icons/imagefloatleft.svg'
        });
        editor.ui.addButton('Image3FloatNone', {
          label: '画像: 回り込みなし',
          command: 'image3FloatNone',
          toolbar: 'align,16',
          icon: this.path + 'icons/imagefloatnone.svg'
        });
        editor.ui.addButton('Image3FloatRight', {
          label: '画像: 右回り込み',
          command: 'image3FloatRight',
          toolbar: 'align,17',
          icon: this.path + 'icons/imagefloatright.svg'
        });
      }

      patchJustifyForParagraph(editor);
      removeCenterFromImage2Dialog();

      var extras = String(editor.config.extraPlugins || '');
      if (extras.indexOf('image2') >= 0 && extras.indexOf('image3') >= 0) {
        // Intentional warning for explicit dual activation in one instance.
        if (window && window.console && console.warn) {
          console.warn('[image3] image2 and image3 are both enabled in this editor instance. This is supported only as transitional setup.');
        }
      }
    }
  });
})();
