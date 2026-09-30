<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed, reactive } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { Backfill, Mailbox } from '@/api/types.gen'
import { ago, arr, count, stamp } from '@/format'
import { useSave } from '@/composables/mutate'
import PageHead from '@/components/PageHead.vue'
import QueryState from '@/components/QueryState.vue'

const query = useQuery({
  queryKey: ['backfills'],
  queryFn: () => api.get<{ backfills: Backfill[]; mailboxes: Mailbox[] }>('/settings/history'),
  // A scan reports progress as it goes, and watching it stall is the point.
  refetchInterval: 5000,
})

const runs = computed(() => arr(query.data.value?.backfills))
const boxes = computed(() => arr(query.data.value?.mailboxes))

const form = reactive({ mailbox_id: '', days: 30, keep_raw: false })

const start = useSave({
  run: () => api.post('/settings/history', { ...form }),
  done: 'Scan started.',
  invalidate: [['backfills']],
})
const cancel = useSave({
  run: (id: string) => api.post(`/settings/history/${encodeURIComponent(id)}/cancel`),
  done: 'Scan cancelled.',
  invalidate: [['backfills']],
})

const addressOf = (id: string) => boxes.value.find((b) => b.id === id)?.address ?? id
const live = (s: string) => s === 'running' || s === 'pending'

// The engine keeps a scan's last error, so that a failure which happened once
// still leaves a record after the scan has moved on. Printed on its own that reads
// as the scan's current condition, and a scan that failed one message out of two
// hundred and forty-two — hours ago, and had been ingesting ever since — looked
// broken. So the error is never shown without the two things that size it: how
// many of how many failed, and when the last one was.
const failureNote = (r: Backfill) => {
  if (!r.failures) return ''
  const of = r.examined ? ` of ${count(r.examined)}` : ''
  const when = r.last_error_at ? `, last ${ago(r.last_error_at)}` : ''
  return `${count(r.failures)}${of} failed${when}`
}

// Within a couple of minutes, which is several progress reports at the rate a
// scan makes them.
const recent = (t?: string) => !!t && Date.now() - Date.parse(t) < 120_000

// Whether the failures are what the scan is *doing*, as opposed to something it
// got past. A finished scan's failures are history whatever their number.
const failing = (r: Backfill) => live(r.state) && !!r.failures && recent(r.last_error_at)
</script>

<template>
  <PageHead
    title="History scans"
    hint="Read mail that arrived before this deployment existed — to find what should not have been delivered, and to give the model something to learn from."
  />

  <form class="panel row form" @submit.prevent="start.mutate()">
    <div>
      <label for="m">Mailbox</label>
      <select id="m" v-model="form.mailbox_id" required>
        <option value="" disabled>choose…</option>
        <option v-for="b in boxes" :key="b.id" :value="b.id">{{ b.address }}</option>
      </select>
    </div>
    <div>
      <label for="d">How far back</label>
      <select id="d" v-model.number="form.days">
        <option :value="30">30 days</option>
        <option :value="60">60 days</option>
        <option :value="90">90 days</option>
      </select>
    </div>
    <label class="inline">
      <input v-model="form.keep_raw" type="checkbox" />
      keep the original bytes, so anything found can be quarantined
    </label>
    <button class="primary" type="submit" :disabled="!form.mailbox_id || start.isPending.value">Start scan</button>
  </form>

  <p class="dim tiny">
    A scan never acts on what it finds — it reads oldest first and records verdicts, so a message
    from two months ago cannot trigger a quarantine today.
  </p>

  <QueryState
    :loading="query.isLoading.value"
    :error="query.error.value"
    :empty="runs.length === 0"
    :has-data="!!query.data.value"
    empty-text="No history scan has been run."
  >
    <table>
      <thead>
        <tr>
          <th>Mailbox</th><th>Range</th><th>State</th>
          <th class="right">Examined</th><th class="right">Ingested</th><th class="right">Flagged</th><th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="r in runs" :key="r.id">
          <td class="mono">{{ addressOf(r.mailbox_id) }}</td>
          <td class="dim nowrap">{{ stamp(r.since) }} → {{ stamp(r.until) }}</td>
          <td>
            <span class="tag" :class="r.state === 'done' ? 'ok' : r.state === 'failed' ? 'bad' : 'act'">{{ r.state }}</span>
            <div v-if="r.cursor" class="tiny faint">at {{ ago(r.cursor) }}</div>
            <div v-if="failureNote(r)" class="tiny" :class="failing(r) ? 'bad-t' : 'faint'">
              {{ failureNote(r) }}
              <span v-if="r.last_error" class="faint why" :title="r.last_error">— {{ r.last_error }}</span>
            </div>
          </td>
          <td class="right mono">{{ count(r.examined) }}</td>
          <td class="right mono">{{ count(r.ingested) }}</td>
          <td class="right mono">{{ count(r.flagged) }}</td>
          <td class="right">
            <button v-if="live(r.state)" class="link" type="button" @click="cancel.mutate(r.id)">cancel</button>
          </td>
        </tr>
      </tbody>
    </table>
  </QueryState>
</template>

<style scoped>
.form { align-items: flex-end; gap: .75rem; margin-bottom: .5rem; }
.inline { display: flex; align-items: center; gap: .4rem; margin: 0 0 .4rem; }
.tiny { font-size: .8rem; }
.bad-t { color: var(--bad); }
/* One error is a diagnostic, not a paragraph: the whole text is in the title. */
.why { display: inline-block; max-width: 34ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: bottom; }
</style>
