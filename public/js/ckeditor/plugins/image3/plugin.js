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
    editor.addCommand(name, new CKEDITOR.command(editor, {
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
    }));
  }

  function applyBlockAlign(block, dir) {
    if (!block) return;
    block.removeAttribute('align');
    if (dir === 'left') {
      block.removeStyle('text-align');
    } else if (dir === 'center' || dir === 'right' || dir === 'justify') {
      block.setStyle('text-align', dir);
    }
  }

  function getBlockAlign(block) {
    if (!block) return '';
    var align = String(block.getStyle('text-align') || block.getAttribute('align') || '').toLowerCase();
    if (align === 'start' || align === 'auto') return 'left';
    return align;
  }

  function wrapJustifyCommands(editor) {
    ['left', 'center', 'right', 'block'].forEach(function(dir) {
      var cmd = editor.getCommand('justify' + dir);
      if (!cmd) return;
      if (cmd._image3Wrapped) return;
      var originalExec = cmd.exec;
      var originalRefresh = cmd.refresh;
      var targetAlign = dir === 'block' ? 'justify' : dir;

      cmd.exec = function(ed) {
        var widget = getFocusedImageWidget(ed || editor);
        if (!widget) {
          return originalExec ? originalExec.apply(this, arguments) : undefined;
        }
        var block = getClosestBlock(widget.wrapper);
        if (!block) return true;
        applyBlockAlign(block, targetAlign);
        (ed || editor).fire('saveSnapshot');
        return true;
      };

      cmd.refresh = function(ed) {
        var widget = getFocusedImageWidget(ed || editor);
        if (!widget) {
          return originalRefresh ? originalRefresh.apply(this, arguments) : undefined;
        }
        var block = getClosestBlock(widget.wrapper);
        if (!block) {
          this.setState(CKEDITOR.TRISTATE_DISABLED);
          return;
        }
        var align = getBlockAlign(block);
        var isOn = targetAlign === 'left' ? (!align || align === 'left') : align === targetAlign;
        this.setState(isOn ? CKEDITOR.TRISTATE_ON : CKEDITOR.TRISTATE_OFF);
      };

      cmd._image3Wrapped = true;
    });
  }

  function bindImageFloatRefresh(editor) {
    function refreshAll() {
      ['image3FloatLeft', 'image3FloatNone', 'image3FloatRight'].forEach(function(name) {
        var cmd = editor.getCommand(name);
        if (cmd && typeof cmd.refresh === 'function') {
          cmd.refresh(editor);
        }
      });
    }
    editor.on('instanceReady', refreshAll);
    editor.on('selectionChange', refreshAll);
    editor.on('afterCommandExec', refreshAll);
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
          toolbar: 'align,50',
          icon: this.path + 'icons/imagefloatleft.svg'
        });
        editor.ui.addButton('Image3FloatNone', {
          label: '画像: 回り込みなし',
          command: 'image3FloatNone',
          toolbar: 'align,60',
          icon: this.path + 'icons/imagefloatnone.svg'
        });
        editor.ui.addButton('Image3FloatRight', {
          label: '画像: 右回り込み',
          command: 'image3FloatRight',
          toolbar: 'align,70',
          icon: this.path + 'icons/imagefloatright.svg'
        });
      }

      editor.on('instanceReady', function() {
        wrapJustifyCommands(editor);
      });
      bindImageFloatRefresh(editor);
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
