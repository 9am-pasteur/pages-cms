<template>
  <div class="h-screen flex justify-center items-center bg-dneutral-200 p-4 lg:p-8">
    <div class="max-w-[360px] text-center">
      <h1 class="font-semibold text-xl lg:text-2xl mb-2">Sign in</h1>
      <p class="text-neutral-400 dark:text-neutral-500 mb-6">Choose an access module to continue.</p>
      <div class="flex flex-col gap-y-3">
        <select v-model="selectedMode" class="w-full">
          <option v-for="m in availableModes" :key="m.id" :value="m.id">{{ m.label }}</option>
        </select>
        <button v-if="isDirectMode" class="btn-primary justify-center w-full !gap-x-3" @click="startOAuth">
          <Icon :name="selectedMode === 'gitlab' ? 'Gitlab' : 'Github'" class="h-6 w-6 stroke-2 shrink-0"/>
          <div>Sign in with {{ currentProvider.label }}</div>
        </button>
        <button v-else class="btn-primary justify-center w-full !gap-x-3" @click="continueWithProxy">
          <Icon name="ShieldCheck" class="h-6 w-6 stroke-2 shrink-0"/>
          <div>Continue with Proxy (GitHub App)</div>
        </button>
        <button v-if="isDirectMode && currentProvider.pat" class="btn-secondary justify-center w-full" @click="patModal.openModal()">
          Sign in with a Personal Access Token
        </button>
      </div>
      <p v-if="bootstrapError" class="text-sm text-red-500 dark:text-red-400 mt-4">{{ bootstrapError }}</p>
    </div>
  </div>
  
  <!-- Fine-grained PAT modal -->
  <Modal v-if="currentProvider.pat" ref="patModal">
    <template #header>Login with a PAT</template>
    <template #content>
      <p class="text-sm mb-2 -mt-1 text-neutral-400 dark:text-neutral-500">
        {{ currentProvider.pat?.hint }}
      </p>
      <input type="text" v-model="patToken" class="w-full"/>
      <div v-if="patToken && !patRegex.test(patToken)" class="mt-2 text-sm text-red-500 dark:text-red-400 flex gap-x-1 items-center">
        <Icon name="Ban" class="h-3 w-3 stroke-[2.5]"/>
        <span>Invalid format for this provider's PAT.</span>
      </div>
      <footer class="flex justify-end text-sm gap-x-2 mt-4">
        <button class="btn-secondary" @click="patModal.closeModal()">Cancel</button>
        <button class="btn-primary" :disabled="!patRegex.test(patToken)" @click="savePat()">Save</button>
      </footer>
    </template>
  </Modal>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import github from '@/services/github';
import Icon from '@/components/utils/Icon.vue';
import Modal from '@/components/utils/Modal.vue';
import providersConfig from '@/config/providers';

const router = useRouter();

const patModal = ref(null);
const patToken = ref('');
const directProviders = providersConfig.filter((p) => p.id === 'github' || p.id === 'gitlab');
const bootstrap = ref(null);
const bootstrapError = ref('');
const fallbackModes = directProviders.map((p) => ({ id: p.id, label: p.label, type: 'direct', enabled: true }));
const availableModes = computed(() => {
  const allModes = bootstrap.value?.modes?.filter((m) => m.enabled) || fallbackModes;
  const allowedIds = Array.isArray(bootstrap.value?.allowedModes) ? bootstrap.value.allowedModes : null;
  const modes = allowedIds
    ? allModes.filter((mode) => allowedIds.includes(mode.id))
    : allModes;
  const resolved = modes.length > 0 ? modes : fallbackModes;

  return resolved.map((mode) => {
    if (mode.id === 'proxy_github_app') {
      return { id: mode.id, label: 'Proxy (GitHub App)' };
    }
    return { id: mode.id, label: mode.label || mode.id };
  });
});
const selectedMode = ref(github.providerId?.value || availableModes.value[0]?.id || 'github');
const isDirectMode = computed(() => selectedMode.value === 'github' || selectedMode.value === 'gitlab');
const currentProvider = computed(() => directProviders.find(p => p.id === selectedMode.value) || directProviders[0]);
const patRegex = computed(() => currentProvider.value?.pat?.regex || /.*/);

const savePat = () => {
  if (patRegex.value.test(patToken.value)) {
    github.setToken(patToken.value, selectedMode.value);
    var redirect = localStorage.getItem('redirect') ? localStorage.getItem('redirect') : '/' ;
    localStorage.removeItem('redirect');
    router.push({ path: redirect });
  }
};

// PKCE helper
const generateCodeVerifier = () => {
  const array = new Uint32Array(56);
  window.crypto.getRandomValues(array);
  return Array.from(array, dec => ('0' + dec.toString(16)).slice(-2)).join('');
};

const sha256 = async (plain) => {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
};

const startOAuth = async () => {
  await github.ensureRuntimeConfig();
  github.setProvider(selectedMode.value);
  const provider = currentProvider.value;
  if (!provider?.oauth?.clientId) {
    alert('Client ID not configured for ' + provider.label);
    return;
  }
  let challenge;
  if (provider.oauth.pkce) {
    const verifier = generateCodeVerifier();
    challenge = await sha256(verifier);
    sessionStorage.setItem('pkce_verifier', verifier);
  } else {
    sessionStorage.removeItem('pkce_verifier');
  }
  sessionStorage.setItem('provider', provider.id);
  const redirect = provider.oauth.redirectUri || (window.location.origin + '/');
  const params = new URLSearchParams({
    client_id: provider.oauth.clientId,
    redirect_uri: redirect,
    response_type: 'code',
    scope: provider.oauth.scopes.join(' '),
    ...(provider.oauth.pkce ? { code_challenge: challenge, code_challenge_method: 'S256' } : {}),
  });
  window.location.href = `${provider.oauth.authorizeUrl}?${params.toString()}`;
};

const continueWithProxy = async () => {
  github.clearToken();
  github.setProvider('proxy_github_app');
  const redirect = localStorage.getItem('redirect') ? localStorage.getItem('redirect') : '/';
  localStorage.removeItem('redirect');
  router.push({ path: redirect });
};

onMounted(async () => {
  const data = await github.getBootstrapSafe(true);
  if (!data) {
    bootstrapError.value = 'Failed to load bootstrap information.';
    return;
  }
  bootstrap.value = data;
  const allowed = data.allowedModes || [];
  if (allowed.length > 0) {
    if (!allowed.includes(selectedMode.value)) {
      selectedMode.value = data.defaultMode || allowed[0];
      github.setProvider(selectedMode.value);
    }
    if (allowed.length === 1 && allowed[0] === 'proxy_github_app') {
      await continueWithProxy();
    }
  }
});

// Runtime provider config is loaded lazily in github.ensureRuntimeConfig (called before OAuth)
</script>
