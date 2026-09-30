<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { User } from '@/api/types.gen'
import { ago, arr } from '@/format'
import { useSave } from '@/composables/mutate'
import PageHead from '@/components/PageHead.vue'
import QueryState from '@/components/QueryState.vue'

const query = useQuery({ queryKey: ['users'], queryFn: () => api.get<{ users: User[] }>('/settings/users') })
const users = computed(() => arr(query.data.value?.users))

const form = reactive({ email: '', name: '', password: '', role: 'viewer' })
const adding = ref(false)

const create = useSave({
  run: () => api.post('/settings/users', { ...form }),
  done: 'Account created.',
  invalidate: [['users']],
})
const update = useSave({
  run: (vars: { id: string; patch: Record<string, unknown> }) =>
    api.patch(`/settings/users/${encodeURIComponent(vars.id)}`, vars.patch),
  done: 'Account updated.',
  invalidate: [['users']],
})

// ---- API tokens ---------------------------------------------------------

const token = reactive({ name: '', role: 'analyst' })
// Shown once, because the engine keeps no recoverable copy.
const issued = ref('')

const mint = useSave({
  run: async () => {
    const out = await api.post<{ token: string }>('/settings/tokens', { ...token })
    issued.value = out.token
    token.name = ''
  },
  done: 'Token created.',
  invalidate: [['users']],
})

function submitUser() {
  create.mutate()
  adding.value = false
}
</script>

<template>
  <PageHead title="Users &amp; tokens" hint="Who can sign in, and which machines may call the API.">
    <template #actions>
      <button class="primary" type="button" @click="adding = !adding">{{ adding ? 'Cancel' : 'Add user' }}</button>
    </template>
  </PageHead>

  <form v-if="adding" class="panel stack add" @submit.prevent="submitUser">
    <div class="grid">
      <div><label for="e">Email</label><input id="e" v-model="form.email" type="email" required autocomplete="off" /></div>
      <div><label for="n">Name</label><input id="n" v-model="form.name" autocomplete="off" /></div>
      <div>
        <label for="p">Password</label>
        <input id="p" v-model="form.password" type="password" required autocomplete="new-password" />
      </div>
      <div>
        <label for="r">Role</label>
        <select id="r" v-model="form.role">
          <option value="viewer">viewer — read only</option>
          <option value="analyst">analyst — may triage and act</option>
          <option value="admin">admin — may change settings</option>
        </select>
      </div>
    </div>
    <div class="row"><button class="primary" type="submit" :disabled="create.isPending.value">Create account</button></div>
  </form>

  <QueryState :loading="query.isLoading.value" :error="query.error.value" :empty="users.length === 0">
    <table>
      <thead><tr><th>Email</th><th>Name</th><th>Role</th><th>Sign-in</th><th>Last seen</th><th></th></tr></thead>
      <tbody>
        <tr v-for="u in users" :key="u.id">
          <td class="mono">{{ u.email }}</td>
          <td>{{ u.name }}</td>
          <td>
            <select
              :value="u.role"
              aria-label="Role"
              @change="update.mutate({ id: u.id, patch: { role: ($event.target as HTMLSelectElement).value } })"
            >
              <option value="viewer">viewer</option>
              <option value="analyst">analyst</option>
              <option value="admin">admin</option>
            </select>
          </td>
          <td class="dim">
            <span v-if="u.local" class="tag mute">password</span>
            <span v-if="u.sso" class="tag act">SSO</span>
          </td>
          <td class="dim nowrap">{{ ago(u.last_login) || 'never' }}</td>
          <td class="right">
            <button
              class="link"
              type="button"
              @click="update.mutate({ id: u.id, patch: { disabled: !u.disabled } })"
            >
              {{ u.disabled ? 'enable' : 'disable' }}
            </button>
          </td>
        </tr>
      </tbody>
    </table>
  </QueryState>

  <h2>API tokens</h2>
  <p class="dim tiny">
    For connectors and scripts. A token carries a role of its own, and mailbox credentials are
    readable by a token — never by a signed-in browser.
  </p>

  <form class="row panel form" @submit.prevent="mint.mutate()">
    <input v-model="token.name" placeholder="what will use it" required aria-label="Token name" />
    <select v-model="token.role" aria-label="Token role">
      <option value="viewer">viewer</option>
      <option value="analyst">analyst</option>
      <option value="admin">admin</option>
    </select>
    <button class="primary" type="submit" :disabled="mint.isPending.value">Create token</button>
  </form>

  <div v-if="issued" class="note issued">
    <strong>Copy this now.</strong> It is not stored anywhere it can be read back.
    <code class="mono">{{ issued }}</code>
    <button class="link" type="button" @click="issued = ''">dismiss</button>
  </div>
</template>

<style scoped>
.add { margin-bottom: 1.25rem; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr)); gap: .75rem; }
.grid input, .grid select { width: 100%; }
.form { gap: .5rem; margin-bottom: .75rem; }
.tiny { font-size: .82rem; }
.issued { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; }
.issued code { overflow-wrap: anywhere; background: var(--panel-2); padding: .15rem .4rem; border-radius: 3px; }
td .tag { margin-right: .25rem; }
</style>
