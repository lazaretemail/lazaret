<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api, ApiError } from '@/api/http'
import { safeNext } from '@/safeNext'
import LazaretMark from '@/components/LazaretMark.vue'
import type { Bootstrap } from '@/api/types.gen'

const email = ref('')
const password = ref('')
const error = ref(new URLSearchParams(location.search).get('error') ?? '')
const busy = ref(false)
const sso = ref(false)

const next = safeNext(new URLSearchParams(location.search).get('next'))

onMounted(async () => {
  try {
    // Already signed in: go where they were headed rather than showing a form that
    // would immediately bounce them.
    await api.get<Bootstrap>('/session')
    location.assign(next)
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      // Expected. Find out whether to offer the SSO button.
      try {
        const cfg = await api.get<{ sso: boolean }>('/auth/config')
        sso.value = cfg.sso
      } catch {
        /* the button is an offer, not a requirement */
      }
    }
  }
})

async function submit() {
  error.value = ''
  busy.value = true
  try {
    await api.post('/auth/login', { email: email.value, password: password.value })
    // A full load, not a route push: the app boots with the new session cookie and
    // an empty query cache rather than whatever the previous identity had fetched.
    location.assign(next)
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
    busy.value = false
  }
}
</script>

<template>
  <div class="wrap">
    <form class="panel card" @submit.prevent="submit">
      <div class="brand">
        <LazaretMark :size="44" title="lazaret" />
        <div class="lockup">
          <div class="wordmark">lazaret</div>
          <div class="rule"></div>
          <div class="descriptor">open-source email detection &amp; response</div>
        </div>
      </div>

      <div v-if="error" class="err">{{ error }}</div>

      <div>
        <label for="email">Email</label>
        <input id="email" v-model="email" type="email" autocomplete="username" required autofocus />
      </div>
      <div>
        <label for="password">Password</label>
        <input id="password" v-model="password" type="password" autocomplete="current-password" required />
      </div>

      <button class="primary" type="submit" :disabled="busy">{{ busy ? 'Signing in…' : 'Sign in' }}</button>

      <a v-if="sso" class="sso" href="/auth/sso">Sign in with your identity provider</a>
    </form>
  </div>
</template>

<style scoped>
.wrap { display: grid; place-items: center; min-height: 100vh; padding: 1rem; }
.card { width: min(23rem, 100%); display: flex; flex-direction: column; gap: .85rem; box-shadow: var(--shadow); }
.brand { display: flex; align-items: center; gap: 1rem; margin-bottom: .35rem; }
.lockup { display: flex; flex-direction: column; gap: .4rem; }
.lockup .wordmark { font-size: 2.1rem; }
/* The amber rule under the wordmark, from the primary lockup. */
.rule { height: 3px; background: var(--amber); }
.descriptor {
  font-family: var(--mono);
  font-size: .68rem;
  letter-spacing: .04em;
  color: var(--dim);
}
input { width: 100%; }
.sso { text-align: center; font-size: .86rem; }
</style>
