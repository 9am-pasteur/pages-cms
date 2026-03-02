<template>
  <template v-if="status == 'loading'">
    <button disabled class="link" :class="[ elementClass ]">
      Loading history
      <div class="spinner-black-sm"></div>
    </button>
  </template>
  <template v-else-if="commitsSafe.length">
    <Dropdown :dropdownClass="'!max-w-none !lg:max-w-full min-w-36'">
      <template #trigger>
        <button class="btn-secondary group-[.dropdown-active]:bg-neutral-100 dark:group-[.dropdown-active]:bg-neutral-850" :class="[ elementClass ]">
          <div class="truncate"><span class="hidden lg:inline">Updated </span>{{ $filters.fromNow(commitsSafe[0].date) }}</div>
        </button>
      </template>
      <template #content>
          <ul>
            <li v-for="commit in commitsSafe.slice(0, 5)">
              <a :href="commit.url" :title="commit.message" target="_blank" class="link">
                <img v-if="commit.avatar" :src="commit.avatar" class="h-5 w-5 rounded-full hidden lg:block"/>
                <div class="truncate">
                  <span class="truncate">{{ $filters.fromNow(commit.date) }}</span>
                </div>
                <Icon name="ExternalLink" class="h-4 w-4 stroke-2 shrink-0 ml-auto text-neutral-400 dark:text-neutral-500"/>
              </a>
            </li>
            <li><hr class="border-t border-neutral-150 dark:border-neutral-750 my-2"/></li>
            <li>
              <a :href="provider.links.repo(owner, repo) + `/commits/${branch}/${path}`" target="_blank" class="link">
                <div>Full history</div>
                <Icon name="ExternalLink" class="h-4 w-4 stroke-2 shrink-0 ml-auto text-neutral-400 dark:text-neutral-500"/>
              </a>
            </li>
          </ul>
      </template>
    </Dropdown>
  </template>
</template>

<script setup>
import { ref, onMounted, watch, computed } from 'vue';
import github from '@/services/github';
import Dropdown from '@/components/utils/Dropdown.vue';
import Icon from '@/components/utils/Icon.vue';

const props = defineProps({
  owner: { type: String },
  repo: { type: String },
  branch: { type: String },
  path: { type: String },
  sha: { type: String },
  elementClass: {
    type: String,
    default: ''
  },
});

const commits = ref([]);
const status = ref('');
const provider = computed(() => github.currentProviderConfig());
const commitsSafe = computed(() => {
  return (commits.value || []).map((c) => {
    const date = c.commit?.author?.date || c.created_at || c.authored_date || null;
    const message = c.commit?.message || c.title || '';
    const url = c.html_url || c.web_url || '#';
    const avatar = c.author?.avatar_url || c.author_avatar_url || null;
    return { date, message, url, avatar };
  }).filter((c) => !!c.date);
});

const setHistory = async () => {
  status.value = 'loading';
  commits.value = await github.getCommits(props.owner, props.repo, props.branch, props.path);
  status.value = '';
};

watch(() => props.sha, (newSha, oldSha) => {
  setHistory();
});

onMounted(async () => {
  setHistory();
});
</script>
