<template>
  <div class="field-date-range">
    <VueDatePicker
      class="w-full"
      :model-value="pickerValue"
      @update:model-value="updateModelValue"
      :range="{ partialRange: false }"
      :model-auto="true"
      :format="displayFormat"
      :min-date="minDate"
      :max-date="maxDate"
      :enable-time-picker="false"
      :hide-input-icon="true"
      auto-apply
    />
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue';
import moment from 'moment';
import VueDatePicker from '@vuepic/vue-datepicker';
import '@vuepic/vue-datepicker/dist/main.css';

const emit = defineEmits(['update:modelValue']);

const props = defineProps({
  field: Object,
  modelValue: String,
});

const saveFormat = computed(() => props.field.options?.format || 'YYYY-MM-DD');
const outputFormat = computed(() => props.field.options?.outputFormat || 'MMM D, YYYY');

const displayFormat = (value) => {
  if (!value) return '';
  if (Array.isArray(value)) {
    const [start, end] = value;
    if (!start) return '';
    if (!end) return moment(start).format(outputFormat.value);
    const startMoment = moment(start);
    const endMoment = moment(end);
    if (startMoment.isSame(endMoment, 'day')) {
      return startMoment.format(outputFormat.value);
    }
    return `${startMoment.format(outputFormat.value)} - ${endMoment.format(outputFormat.value)}`;
  }
  return moment(value).format(outputFormat.value);
};

const toDate = (value, format) => {
  if (!value) return null;
  const parsed = moment(value, format, true);
  if (!parsed.isValid()) return null;
  return parsed.toDate();
};

const parseInterval = (value) => {
  if (!value || typeof value !== 'string') return [null, null];
  if (!value.includes('/')) {
    const date = toDate(value, saveFormat.value);
    return [date, date];
  }
  const [startRaw, endRaw] = value.split('/');
  return [toDate(startRaw, saveFormat.value), toDate(endRaw, saveFormat.value)];
};

const parsePickerValue = (value) => {
  const [start, end] = parseInterval(value);
  if (!start || !end) return null;
  return [start, end];
};

const pickerValue = ref(parsePickerValue(props.modelValue));

watch(
  () => props.modelValue,
  (nextValue) => {
    pickerValue.value = parsePickerValue(nextValue);
  },
);

const minDate = computed(() => toDate(props.field.options?.min, saveFormat.value));
const maxDate = computed(() => toDate(props.field.options?.max, saveFormat.value));

const updateModelValue = (value) => {
  pickerValue.value = value;

  if (!value) {
    emit('update:modelValue', '');
    return;
  }

  if (!Array.isArray(value) || value.length < 2 || !value[0] || !value[1]) {
    if (Array.isArray(value) && value[0]) {
      pickerValue.value = [value[0], null];
    }
    return;
  }

  const start = moment(value[0]);
  const end = moment(value[1]);
  if (!start.isValid() || !end.isValid()) {
    return;
  }
  emit('update:modelValue', `${start.format(saveFormat.value)}/${end.format(saveFormat.value)}`);
};
</script>

<style scoped>
.field-date-range :deep(.dp__input_wrap),
.field-date-range :deep(.dp__input) {
  width: 100%;
}

.field-date-range :deep(.dp__input) {
  border-radius: 0.75rem;
  border-width: 1px;
  --tw-border-opacity: 1;
  border-color: rgb(237 237 237 / var(--tw-border-opacity));
  --tw-bg-opacity: 1;
  background-color: rgb(237 237 237 / var(--tw-bg-opacity));
  transition-property: all;
  transition-timing-function: cubic-bezier(.4, 0, .2, 1);
  transition-duration: .15s;
  padding: 0.375rem 0.625rem;
}

.field-date-range :deep(.dp__input:focus),
.field-date-range :deep(.dp__input_focus) {
  --tw-border-opacity: 1;
  border-color: rgb(10 10 10 / var(--tw-border-opacity));
  box-shadow: none;
}

@media (min-width: 1024px) {
  .field-date-range :deep(.dp__input) {
    padding: 0.5rem 0.75rem;
  }
}

:global(.dark) .field-date-range :deep(.dp__input) {
  --tw-border-opacity: 1;
  border-color: rgb(38 38 38 / var(--tw-border-opacity));
  --tw-bg-opacity: 1;
  background-color: rgb(38 38 38 / var(--tw-bg-opacity));
}

:global(.dark) .field-date-range :deep(.dp__input:focus),
:global(.dark) .field-date-range :deep(.dp__input_focus) {
  --tw-border-opacity: 1;
  border-color: rgb(255 255 255 / var(--tw-border-opacity));
}
</style>
