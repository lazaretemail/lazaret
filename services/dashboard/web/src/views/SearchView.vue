<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed, ref } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { Message } from '@/api/types.gen'
import { ago, arr, iso, short } from '@/format'
import PageHead from '@/components/PageHead.vue'
import QueryState from '@/components/QueryState.vue'
import WindowPicker from '@/components/WindowPicker.vue'
import VerdictTag from '@/components/VerdictTag.vue'

const q = ref('')
const sender = ref('')
const verdict = ref('')
const window = ref('30')
const submitted = ref({ q: '', sender: '', verdict: '', window: '30' })

function run() {
  submitted.value = { q: q.value, sender: sender.value, verdict: verdict.value, window: window.value }
}

const query = useQuery({
  queryKey: computed(() => ['search', submitted.value]),
  // Enabled only once something has been asked for: an empty search would otherwise
  // pull the whole window on first paint.
  enabled: computed(() => !!(submitted.value.q || submitted.value.sender || submitted.value.verdict)),
  queryFn: () => api.get<{ messages: Message[] }>('/search', submitted.value),
})

const messages = computed(() => arr(query.data.value?.messages))
const asked = computed(() => !!(submitted.value.q || submitted.value.sender || submitted.value.verdict))
</script>

<template>
  <PageHead title="Search" hint="Find a message by subject, sender or verdict." />

  <form class="panel row filters" @submit.prevent="run">
    <input v-model="q" type="search" placeholder="Subject contains…" aria-label="Subject" />
    <input v-model="sender" type="search" placeholder="Sender…" aria-label="Sender" />
    <select v-model="verdict" aria-label="Verdict">
      <option value="">any verdict</option>
      <option value="malicious">malicious</option>
      <option value="indeterminate">indeterminate</option>
      <option value="clean">clean</option>
    </select>
    <WindowPicker v-model="window" />
    <button class="primary" type="submit">Search</button>
  </form>

  <p v-if="!asked" class="dim">Enter something to search for.</p>

  <QueryState
    v-else
    :loading="query.isLoading.value"
    :error="query.error.value"
    :empty="messages.length === 0"
    empty-text="No message matched."
  >
    <table>
      <thead><tr><th>Subject</th><th>Sender</th><th>Verdict</th><th class="nowrap">Received</th></tr></thead>
      <tbody>
        <tr v-for="m in messages" :key="m.message_id">
          <td><RouterLink :to="`/messages/${encodeURIComponent(m.message_id)}`">{{ short(m.subject, 90) || '(no subject)' }}</RouterLink></td>
          <td class="mono">{{ short(m.sender, 40) }}</td>
          <td><VerdictTag :verdict="m.verdict" /></td>
          <td class="nowrap dim" :title="iso(m.received_at)">{{ ago(m.received_at) }}</td>
        </tr>
      </tbody>
    </table>
  </QueryState>
</template>

<style scoped>
.filters { margin-bottom: 1rem; }
</style>
