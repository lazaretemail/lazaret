<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { TriagePage, Message } from '@/api/types.gen'
import { useSession } from '@/composables/session'
import { toast } from '@/composables/toast'
import { ago, arr, iso, short, count } from '@/format'
import PageHead from '@/components/PageHead.vue'
import QueryState from '@/components/QueryState.vue'
import WindowPicker from '@/components/WindowPicker.vue'
import VerdictTag from '@/components/VerdictTag.vue'

const route = useRoute()
const router = useRouter()
const qc = useQueryClient()
const { data: session } = useSession()

// Filter state lives in the URL, so a queue view is a link somebody can paste into a
// ticket and a browser Back goes where it looks like it should.
const state = computed(() => String(route.query.state ?? 'needs_remediation'))
const window = computed(() => String(route.query.window ?? '30'))
const search = ref(String(route.query.q ?? ''))

function setQuery(patch: Record<string, string | undefined>) {
  router.replace({ query: { ...route.query, ...patch } })
}

let debounce: ReturnType<typeof setTimeout>
watch(search, (v) => {
  clearTimeout(debounce)
  debounce = setTimeout(() => setQuery({ q: v || undefined }), 250)
})

const query = useQuery({
  queryKey: computed(() => ['triage', state.value, window.value, route.query.q ?? '']),
  queryFn: () =>
    api.get<TriagePage>('/triage', {
      state: state.value,
      window: window.value,
      q: String(route.query.q ?? ''),
    }),
  // A queue is a live thing; a message quarantined by a colleague should leave the
  // list without anyone reloading.
  refetchInterval: 20_000,
  placeholderData: (prev) => prev,
})

const messages = computed<Message[]>(() => query.data.value?.messages ?? [])
const queue = computed(() => session.value?.queues.find((q) => q.key === state.value))

// ---- selection ----------------------------------------------------------

const selected = ref<Set<string>>(new Set())
// Clearing on filter change: keeping a selection across queues means a bulk action
// could apply to rows that are no longer on screen.
watch([state, window, () => route.query.q], () => selected.value.clear())

const allShown = computed(() => messages.value.length > 0 && messages.value.every((m) => selected.value.has(m.message_id)))

function toggle(id: string) {
  const next = new Set(selected.value)
  next.has(id) ? next.delete(id) : next.add(id)
  selected.value = next
}
function toggleAll() {
  selected.value = allShown.value ? new Set() : new Set(messages.value.map((m) => m.message_id))
}

// ---- bulk triage --------------------------------------------------------

const bulk = useMutation({
  mutationFn: (vars: { ids: string[]; state: string }) =>
    api.post<{ done: number; failed?: Record<string, string> }>('/triage/bulk', vars),
  onSuccess: (res, vars) => {
    if (res.failed) {
      // Leave the failures selected so the next attempt is one click, and say how
      // many actually landed rather than claiming the whole batch worked.
      selected.value = new Set(Object.keys(res.failed))
      toast.err(`${res.done} of ${vars.ids.length} updated; ${Object.keys(res.failed).length} refused`)
    } else {
      selected.value = new Set()
      toast.ok(`${res.done} message${res.done === 1 ? '' : 's'} moved to ${vars.state.replace('_', ' ')}`)
    }
    qc.invalidateQueries({ queryKey: ['triage'] })
    qc.invalidateQueries({ queryKey: ['session'] })
  },
  onError: (e) => toast.err(e),
})

function applyBulk(to: string) {
  if (selected.value.size === 0) return
  bulk.mutate({ ids: [...selected.value], state: to })
}

const targets = computed(() => (session.value?.queues ?? []).filter((q) => q.key !== 'all' && q.key !== state.value))
</script>

<template>
  <PageHead :title="queue?.label ?? 'Triage'" :hint="queue?.hint">
    <template #actions>
      <input
        v-model="search"
        type="search"
        placeholder="Filter by subject or sender…"
        aria-label="Filter messages"
        style="min-width: 17rem"
      />
      <WindowPicker :model-value="window" @update:model-value="(v) => setQuery({ window: v })" />
    </template>
  </PageHead>

  <!-- The bulk bar only exists when it can do something, so it never sits there greyed out. -->
  <div v-if="selected.size > 0" class="bulk panel">
    <strong>{{ count(selected.size) }} selected</strong>
    <span class="dim">move to</span>
    <button
      v-for="t in targets"
      :key="t.key"
      type="button"
      :disabled="bulk.isPending.value"
      @click="applyBulk(t.key)"
    >
      {{ t.label }}
    </button>
    <button class="link" type="button" @click="selected = new Set()">clear</button>
  </div>

  <QueryState
    :loading="query.isLoading.value"
    :error="query.error.value"
    :empty="messages.length === 0"
    :has-data="!!query.data.value"
    empty-text="Nothing in this queue for the chosen window."
  >
    <table>
      <thead>
        <tr>
          <th style="width: 2rem">
            <input
              type="checkbox"
              :checked="allShown"
              aria-label="Select all shown"
              @change="toggleAll"
            />
          </th>
          <th>Subject</th>
          <th>Sender</th>
          <th>Verdict</th>
          <th>Rules</th>
          <th class="nowrap">Received</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="m in messages" :key="m.message_id" :class="{ picked: selected.has(m.message_id) }">
          <td>
            <input
              type="checkbox"
              :checked="selected.has(m.message_id)"
              :aria-label="`Select ${m.subject || 'message'}`"
              @change="toggle(m.message_id)"
            />
          </td>
          <td>
            <RouterLink :to="`/messages/${encodeURIComponent(m.message_id)}`">
              {{ short(m.subject, 90) || '(no subject)' }}
            </RouterLink>
            <div v-if="arr(m.missing).length" class="miss faint">
              unavailable: {{ arr(m.missing).join(', ') }}
            </div>
          </td>
          <td class="mono">{{ short(m.sender, 40) }}</td>
          <td><VerdictTag :verdict="m.verdict" /></td>
          <td>
            <span v-for="r in arr(m.matched).slice(0, 3)" :key="r" class="rule">{{ r }}</span>
            <span v-if="m.matched.length > 3" class="faint">+{{ m.matched.length - 3 }}</span>
          </td>
          <td class="nowrap dim" :title="iso(m.received_at)">{{ ago(m.received_at) }}</td>
        </tr>
      </tbody>
    </table>
  </QueryState>
</template>

<style scoped>
.bulk {
  position: sticky;
  top: .5rem;
  z-index: 10;
  display: flex;
  gap: .5rem;
  align-items: center;
  flex-wrap: wrap;
  margin-bottom: .75rem;
  padding: .55rem .8rem;
  box-shadow: var(--shadow);
}
tr.picked { background: color-mix(in srgb, var(--accent) 8%, transparent); }
.rule {
  display: inline-block;
  font-size: .75rem;
  background: var(--panel-2);
  border: 1px solid var(--line);
  border-radius: 3px;
  padding: 0 .35rem;
  margin: 0 .2rem .2rem 0;
}
.miss { font-size: .76rem; margin-top: .15rem; }
</style>
