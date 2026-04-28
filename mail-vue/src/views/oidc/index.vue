<template>
  <div class="oidc-page" v-loading="true" element-loading-text="登录中..."></div>
</template>

<script setup>
import {onMounted} from 'vue';
import router from '@/router/index.js';
import {useSettingStore} from '@/store/setting.js';
import {useUserStore} from '@/store/user.js';
import {useAccountStore} from '@/store/account.js';
import {useUiStore} from '@/store/ui.js';
import {oauthOidcLogin} from '@/request/ouath.js';
import {loginUserInfo} from '@/request/my.js';
import {permsToRouter} from '@/perm/perm.js';

const oidcFlowKey = 'cloud-mail-oidc-flow';
const settingStore = useSettingStore();
const userStore = useUserStore();
const accountStore = useAccountStore();
const uiStore = useUiStore();

onMounted(() => {
  oidcEnter();
});

async function oidcEnter() {
  const token = localStorage.getItem('token');
  if (token) {
    await router.replace({name: 'layout'});
    return;
  }

  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  const state = params.get('state');

  if (code || state) {
    await oidcCallback(code, state);
    return;
  }

  await startOidcLogin();
}

async function oidcCallback(code, state) {
  const flow = oidcFlow();
  if (!code || !state || flow.state !== state) {
    localStorage.removeItem(oidcFlowKey);
    await router.replace({name: 'login'});
    return;
  }

  oauthOidcLogin(code, flow.codeVerifier).then(async data => {
    await saveToken(data.token);
  }).catch(async () => {
    await router.replace({name: 'login'});
  }).finally(() => {
    localStorage.removeItem(oidcFlowKey);
    const cleanUrl = window.location.origin + window.location.pathname;
    window.history.replaceState({}, '', cleanUrl);
  });
}

async function startOidcLogin() {
  const clientId = settingStore.settings.oidcClientId;
  const authorizeUrl = settingStore.settings.oidcAuthorizeUrl;
  const redirectUri = settingStore.settings.oidcCallbackUrl;
  if (!clientId || !authorizeUrl || !redirectUri) {
    ElMessage({
      message: 'OIDC配置不完整',
      type: 'error',
      plain: true,
    });
    await router.replace({name: 'login'});
    return;
  }

  const state = randomUrlSafeString(24);
  const codeVerifier = randomUrlSafeString(64);
  const codeChallenge = await pkceChallenge(codeVerifier);
  localStorage.setItem(oidcFlowKey, JSON.stringify({state, codeVerifier}));

  const url = new URL(authorizeUrl);
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', settingStore.settings.oidcScope || 'openid profile email');
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  window.location.href = url.toString();
}

async function saveToken(token) {
  localStorage.setItem('token', token);
  const user = await loginUserInfo();
  accountStore.currentAccountId = user.account.accountId;
  accountStore.currentAccount = user.account;
  userStore.user = user;
  const routers = permsToRouter(user.permKeys);
  routers.forEach(routerData => {
    router.addRoute('layout', routerData);
  });
  await router.replace({name: 'layout'});
  uiStore.showNotice();
}

function oidcFlow() {
  try {
    return JSON.parse(localStorage.getItem(oidcFlowKey) || '{}');
  } catch (e) {
    return {};
  }
}

function randomUrlSafeString(length) {
  const bytes = new Uint8Array(length);
  window.crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

async function pkceChallenge(codeVerifier) {
  const digest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
  return base64UrlEncode(new Uint8Array(digest));
}

function base64UrlEncode(bytes) {
  let binary = '';
  bytes.forEach(byte => binary += String.fromCharCode(byte));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
</script>

<style scoped>
.oidc-page {
  width: 100vw;
  height: 100vh;
}
</style>
