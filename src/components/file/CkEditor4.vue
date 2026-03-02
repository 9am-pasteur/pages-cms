<template>
  <div class="relative">
    <div v-if="status === 'loading'" class="bg-neutral-150 dark:bg-neutral-800 border-neutral-150 dark:border-neutral-800 py-2 px-3 h-24 rounded-xl flex items-center justify-center absolute inset-0 z-10">
      <div class="spinner-black"></div>
    </div>
    <textarea ref="textareaEl"></textarea>
    <p v-if="status === 'error'" class="text-red-500 mt-2 text-sm">CKEditor 4 が読み込まれていません。`public/js/ckeditor/ckeditor.js` を配置してください。</p>
  </div>
</template>

<script setup>
// Minimal CKEditor4 wrapper with Markdown/HTML in/out parity to TipTap
import { inject, onMounted, onBeforeUnmount, ref, watch } from 'vue';
import { marked } from 'marked';
import TurndownService from 'turndown';
import githubImg from '@/services/githubImg';

const emit = defineEmits(['update:modelValue']);

const repoStore = inject('repoStore', { owner: null, repo: null, branch: null, config: null, details: null });

const props = defineProps({
  owner: String,
  repo: String,
  branch: String,
  options: Object,
  modelValue: String,
  format: { type: String, default: 'markdown' },
  private: { type: Boolean, default: false },
});

const textareaEl = ref(null);
const ck = ref(null);
const status = ref('loading');

// Lazy-load CKEditor script from /js/ckeditor/ckeditor.js when not present.
let ckLoaderPromise = null;
const ensureCkEditor = () => {
  if (window && window.CKEDITOR) return Promise.resolve(window.CKEDITOR);
  if (ckLoaderPromise) return ckLoaderPromise;
  ckLoaderPromise = new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = `${import.meta.env.BASE_URL || '/'}js/ckeditor/ckeditor.js`;
    script.onload = () => window.CKEDITOR ? resolve(window.CKEDITOR) : reject(new Error('CKEDITOR not available after load'));
    script.onerror = () => reject(new Error('Failed to load CKEditor script'));
    document.head.appendChild(script);
  });
  return ckLoaderPromise;
};

const prefixInput = ref(props.options?.input ?? repoStore?.config?.object?.media?.input ?? null);
const prefixOutput = ref(props.options?.output ?? repoStore?.config?.object?.media?.output ?? null);

const turndownService = new TurndownService({ headingStyle: 'atx', codeBlockStyle: 'fenced' });
turndownService.addRule('styled-or-classed', {
  filter: (node) => ((node.nodeName === 'IMG' && (node.getAttribute('width') || node.getAttribute('height'))) || node.getAttribute('style') || node.getAttribute('class')),
  replacement: (_content, node) => node.outerHTML,
});

const importContent = async (content) => {
  let htmlContent = (props.format === 'markdown') ? marked.parse(content || '') : (content || '');
  htmlContent = githubImg.htmlSwapPrefix(htmlContent, prefixOutput.value, prefixInput.value, true);
  htmlContent = await githubImg.relativeToRawUrls(repoStore.owner, repoStore.repo, repoStore.branch, htmlContent, repoStore.details?.private);
  return htmlContent;
};

const exportContent = (content) => {
  let htmlContent = githubImg.rawToRelativeUrls(repoStore.owner, repoStore.repo, repoStore.branch, content);
  htmlContent = githubImg.htmlSwapPrefix(htmlContent, prefixInput.value, prefixOutput.value);
  if (props.format === 'markdown') {
    return turndownService.turndown(htmlContent);
  } else if (props.format === 'html') {
    return htmlContent.replace(/(<(?:br|hr) ?\/>|<\/(?:p|div|td|tr|table|h\d)>|<(?:tr|tbody)>)/g, "$1\n");
  }
  return htmlContent;
};

const setEditorData = async (value) => {
  if (!ck.value) return;
  const htmlContent = await importContent(value ?? '');
  ck.value.setData(htmlContent);
};

onMounted(async () => {
  try {
    const CKEDITOR = await ensureCkEditor();
    ck.value = CKEDITOR.replace(textareaEl.value, {
      language: 'ja',
      extraPlugins: 'cloudinary,justify',
      versionCheck: false, // suppress LTSアップグレード通知（4.22.1 OSS固定運用向け）
      // 呼び出し元で上書き可能
      ...(props.options?.ckeditorConfig || {}),
    });

    ck.value.on('instanceReady', async () => {
      await setEditorData(props.modelValue);
      status.value = '';
    });

    ck.value.on('change', () => {
      const data = ck.value.getData();
      emit('update:modelValue', exportContent(data));
    });
  } catch (e) {
    console.error(e);
    status.value = 'error';
  }
});

watch(() => props.modelValue, async (val) => {
  // 親から値が変わったときのみ反映（自分のchange発火とのループを避けるため簡易比較）
  if (ck.value && exportContent(ck.value.getData()) !== val) {
    await setEditorData(val);
  }
});

onBeforeUnmount(() => {
  if (ck.value) {
    ck.value.destroy(true);
    ck.value = null;
  }
});
</script>
