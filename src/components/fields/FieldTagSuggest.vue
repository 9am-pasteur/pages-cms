<template>
  <div class="relative">
    <div
      class="w-full min-h-[2.5rem] flex flex-wrap items-center gap-1.5 cursor-text border rounded-xl transition-all px-2.5 py-1.5 lg:px-3 lg:py-2 bg-neutral-150 border-neutral-150 dark:bg-neutral-800 dark:border-neutral-800 focus-within:border-neutral-950 dark:focus-within:border-white"
      @click="focusInput"
    >
      <span
        v-for="(tag, index) in tags"
        :key="`${tag}-${index}`"
        class="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-sm border bg-orange-100 text-orange-900 border-orange-200 dark:bg-orange-900/30 dark:text-orange-100 dark:border-orange-700"
      >
        <button type="button" class="hover:underline" @click.stop="toggleTagDetails(tag)">
          {{ tag }}
        </button>
        <button class="inline-flex" type="button" @click.stop="removeTag(index)">
          <Icon name="X" class="h-3 w-3 stroke-[2.5]"/>
        </button>
      </span>
      <input
        ref="inputEl"
        class="flex-1 min-w-[8rem] bg-transparent border-0 focus:ring-0 p-0"
        type="text"
        :placeholder="placeholder"
        v-model="query"
        @focus="handleFocus"
        @blur="handleBlur"
        @keydown="handleKeydown"
      />
    </div>

    <div
      v-if="activeTagDetail"
      class="mt-2 rounded-xl border border-neutral-200 dark:border-neutral-750 bg-white dark:bg-neutral-950 px-3 py-2"
    >
      <div class="flex items-center gap-x-2">
        <div class="font-medium">{{ activeTagDetail.tag }}</div>
        <button class="btn-icon-secondary-sm ml-auto" type="button" @click="activeTagKey = ''">
          <Icon name="X" class="h-3.5 w-3.5 stroke-2.5"/>
        </button>
      </div>
      <div v-if="isDetailLoading" class="mt-1 text-sm text-neutral-400 dark:text-neutral-500">Loading description...</div>
      <div
        v-else
        class="mt-1 text-sm text-neutral-500 dark:text-neutral-400 prose prose-sm dark:prose-invert max-w-none"
        v-html="renderDescription(activeTagDetail.description)"
      />
    </div>

    <div
      v-if="dropdownVisible"
      class="absolute z-50 mt-2 w-full max-h-80 overflow-y-auto rounded-xl border border-neutral-200 dark:border-neutral-750 bg-white dark:bg-neutral-950 custom-shadow"
    >
      <div v-if="loading" class="px-3 py-2 text-sm text-neutral-400 dark:text-neutral-500">Loading suggestions...</div>
      <div v-else-if="suggestions.length === 0" class="px-3 py-2 text-sm text-neutral-400 dark:text-neutral-500">No suggestions</div>
      <ul v-else>
        <li v-for="item in suggestions" :key="item.tag">
          <button
            class="w-full text-left px-3 py-2 hover:bg-neutral-100 dark:hover:bg-neutral-850 transition-colors"
            type="button"
            @mousedown.prevent="selectSuggestion(item.tag)"
          >
            <div class="font-medium">{{ item.tag }}</div>
            <div
              v-if="item.description"
              class="text-sm text-neutral-500 dark:text-neutral-400 prose prose-sm dark:prose-invert max-w-none"
              v-html="renderDescription(item.description)"
            />
          </button>
        </li>
      </ul>
    </div>

    <ul v-if="errors.length" class="mt-2 text-sm text-red-500 dark:text-red-400">
      <li v-for="error in errors" :key="error" class="flex gap-x-1 items-center">
        <Icon name="Ban" class="h-3 w-3 stroke-[2.5]"/>
        {{ error }}
      </li>
    </ul>
  </div>
</template>

<script setup>
import { computed, onUnmounted, ref, watch } from 'vue';
import { debounce } from 'lodash';
import Icon from '@/components/utils/Icon.vue';
import useFieldValidation from '@/composables/useFieldValidation';
import useSchema from '@/composables/useSchema';

const emit = defineEmits(['update:modelValue']);
const props = defineProps({
  field: Object,
  modelValue: String,
  record: Object,
});

const { validateRequired, validatePattern, validateLength } = useFieldValidation();
const { renderDescription } = useSchema();

const inputEl = ref(null);
const query = ref('');
const tags = ref([]);
const suggestions = ref([]);
const loading = ref(false);
const hasFetched = ref(false);
const errors = ref([]);
const isFocused = ref(false);
const initialFetchTimer = ref(null);
const abortController = ref(null);
const detailAbortController = ref(null);
const blurTimer = ref(null);
const tagDetails = ref({});
const activeTagKey = ref('');
const detailLoadingKey = ref('');

const placeholder = computed(() => props.field.options?.placeholder || 'Type a tag...');
const provider = computed(() => String(props.field.options?.suggestProvider || '').trim());
const minQueryLength = computed(() => Number(props.field.options?.minQueryLength) || 0);
const contextFields = computed(() => Array.isArray(props.field.options?.contextFields) ? props.field.options.contextFields : []);
const dropdownVisible = computed(() => isFocused.value && (loading.value || hasFetched.value));
const activeTagDetail = computed(() => {
  const key = activeTagKey.value;
  if (!key) return null;
  return tagDetails.value[key] || null;
});
const isDetailLoading = computed(() => !!detailLoadingKey.value && detailLoadingKey.value === activeTagKey.value);

const normalizeTag = (value) => String(value || '').trim().replace(/\s+/g, ' ');

const parseTags = (value) => {
  if (!value) return [];
  return String(value)
    .split(',')
    .map((entry) => normalizeTag(entry))
    .filter(Boolean);
};

const serializeTags = (value) => value.join(', ');
const tagKey = (value) => normalizeTag(value).toLowerCase();

const emitTags = () => {
  emit('update:modelValue', serializeTags(tags.value));
};

const setTagsFromModel = (value) => {
  tags.value = parseTags(value);
  if (activeTagKey.value && !tags.value.some((tag) => tagKey(tag) === activeTagKey.value)) {
    activeTagKey.value = '';
  }
};

watch(() => props.modelValue, (nextValue) => {
  setTagsFromModel(nextValue);
}, { immediate: true });

const collectRecord = () => {
  if (!props.record || !contextFields.value.length) return {};
  return contextFields.value.reduce((acc, fieldName) => {
    acc[fieldName] = props.record[fieldName];
    return acc;
  }, {});
};

const requestSuggestions = async (queryValue, signal) => {
  const response = await fetch('/api/tag-suggest', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      provider: provider.value,
      query: queryValue,
      tokens: tags.value,
      record: collectRecord(),
      field: props.field.name,
    }),
    signal,
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) return [];
  return Array.isArray(data.items) ? data.items : [];
};

const cacheKnownTagDetails = (items) => {
  for (const item of items) {
    const normalizedTag = normalizeTag(item?.tag);
    const description = String(item?.description || '').trim();
    if (!normalizedTag || !description) continue;
    const key = tagKey(normalizedTag);
    if (tags.value.some((tag) => tagKey(tag) === key)) {
      tagDetails.value[key] = { tag: normalizedTag, description };
    }
  }
};

const fetchSuggestions = async () => {
  if (!provider.value) {
    suggestions.value = [];
    hasFetched.value = false;
    return;
  }
  if (query.value.length < minQueryLength.value) {
    suggestions.value = [];
    hasFetched.value = false;
    return;
  }

  abortController.value?.abort();
  abortController.value = new AbortController();
  loading.value = true;

  try {
    const items = await requestSuggestions(query.value, abortController.value.signal);
    cacheKnownTagDetails(items);
    const selected = new Set(tags.value.map((tag) => tag.toLowerCase()));
    suggestions.value = items
      ? items.filter((item) => !selected.has(String(item.tag || '').toLowerCase()))
      : [];
  } catch (error) {
    if (error?.name !== 'AbortError') {
      suggestions.value = [];
    }
  } finally {
    hasFetched.value = true;
    loading.value = false;
  }
};

const fetchTagDetail = async (tag) => {
  if (!provider.value) return false;
  const key = tagKey(tag);
  detailAbortController.value?.abort();
  detailAbortController.value = new AbortController();
  detailLoadingKey.value = key;
  try {
    const items = await requestSuggestions(tag, detailAbortController.value.signal);
    cacheKnownTagDetails(items);
    const exact = items.find((item) => tagKey(item?.tag) === key && String(item?.description || '').trim());
    if (exact) {
      tagDetails.value[key] = {
        tag: normalizeTag(exact.tag),
        description: String(exact.description || '').trim(),
      };
      return true;
    }
    return !!tagDetails.value[key]?.description;
  } catch (error) {
    if (error?.name === 'AbortError') return false;
    return false;
  } finally {
    if (detailLoadingKey.value === key) {
      detailLoadingKey.value = '';
    }
  }
};

const debouncedFetch = debounce(fetchSuggestions, 350);

watch(query, () => {
  debouncedFetch();
});

const addTag = (value) => {
  const normalized = normalizeTag(value);
  if (!normalized) return false;
  const lower = normalized.toLowerCase();
  if (tags.value.some((tag) => tag.toLowerCase() === lower)) return false;
  tags.value.push(normalized);
  emitTags();
  return true;
};

const commitQuery = () => {
  if (addTag(query.value)) {
    query.value = '';
    suggestions.value = [];
  }
};

const removeTag = (index) => {
  const removedTag = tags.value[index];
  tags.value.splice(index, 1);
  if (removedTag && tagKey(removedTag) === activeTagKey.value) {
    activeTagKey.value = '';
  }
  emitTags();
};

const selectSuggestion = (tag) => {
  if (addTag(tag)) {
    query.value = '';
    suggestions.value = [];
    hasFetched.value = false;
    fetchSuggestions();
  }
  focusInput();
};

const handleKeydown = (event) => {
  if (event.key === ',' || event.key === 'Enter' || event.key === 'Tab') {
    if (query.value.trim()) {
      event.preventDefault();
      commitQuery();
    }
    return;
  }
  if (event.key === 'Backspace' && !query.value && tags.value.length > 0) {
    removeTag(tags.value.length - 1);
  }
};

const handleFocus = () => {
  isFocused.value = true;
  activeTagKey.value = '';
  if (blurTimer.value) {
    clearTimeout(blurTimer.value);
    blurTimer.value = null;
  }
  if (initialFetchTimer.value) clearTimeout(initialFetchTimer.value);
  initialFetchTimer.value = setTimeout(() => {
    if (isFocused.value) fetchSuggestions();
  }, 1000);
};

const handleBlur = () => {
  blurTimer.value = setTimeout(() => {
    isFocused.value = false;
    suggestions.value = [];
    hasFetched.value = false;
  }, 120);
};

const focusInput = () => {
  inputEl.value?.focus();
};

const toggleTagDetails = async (tag) => {
  const key = tagKey(tag);
  if (activeTagKey.value === key) {
    activeTagKey.value = '';
    return;
  }
  activeTagKey.value = key;
  if (tagDetails.value[key]?.description) return;
  const ok = await fetchTagDetail(tag);
  if (!ok && activeTagKey.value === key) {
    activeTagKey.value = '';
  }
};

onUnmounted(() => {
  debouncedFetch.cancel();
  abortController.value?.abort();
  detailAbortController.value?.abort();
  if (initialFetchTimer.value) clearTimeout(initialFetchTimer.value);
  if (blurTimer.value) clearTimeout(blurTimer.value);
});

const validate = () => {
  errors.value = [];
  const value = serializeTags(tags.value);
  const requiredError = validateRequired(props.field, value);
  const patternError = validatePattern(props.field, value);
  const lengthError = validateLength(props.field, value);
  if (requiredError.length) errors.value = errors.value.concat(requiredError);
  if (patternError.length) errors.value = errors.value.concat(patternError);
  if (lengthError.length) errors.value = errors.value.concat(lengthError);
  return errors.value;
};

defineExpose({ validate });
</script>
