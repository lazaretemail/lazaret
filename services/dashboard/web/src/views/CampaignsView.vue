<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
/**
 * One attack, grouped instead of triaged thirty times.
 *
 * The number at the top is the claim the page makes: how much of the window collapses
 * into how few decisions. Without the messages-considered figure, "8 campaigns" says
 * nothing — it could be eight groups out of twelve messages or out of twelve thousand.
 *
 * The split-verdict marker is the reason to look here even when the queue is quiet.
 * Twenty-nine of a campaign judged malicious and one not is a miss with its own
 * evidence attached, and it is invisible message by message.
 */
import { computed, ref } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { Campaigns, Campaign } from '@/api/types.gen'
import { ago, arr, count, iso, short } from '@/format'
import PageHead from '@/components/PageHead.vue'
import QueryState from '@/components/QueryState.vue'
import WindowPicker from '@/components/WindowPicker.vue'
import VerdictTag from '@/components/VerdictTag.vue'

const window = ref('30')
const expanded = ref<string | null>(null)

const q = useQuery({
  queryKey: computed(() => ['campaigns', window.value]),
  queryFn: () => api.get<Campaigns>('/campaigns', { window: window.value }),
})

const campaigns = computed(() => arr(q.data.value?.campaigns))
const considered = computed(() => q.data.value?.messages_considered ?? 0)
const grouped = computed(() => q.data.value?.messages_grouped ?? 0)

/** A campaign the deployment did not judge consistently. */
function split(c: Campaign): boolean {
  return Object.keys(c.verdicts ?? {}).length > 1
}

/** The verdicts as "4 malicious · 1 none", most common first. */
function verdicts(c: Campaign): string {
  return Object.entries(c.verdicts ?? {})
    .sort((a, b) => b[1] - a[1])
    .map(([v, n]) => `${n} ${v}`)
    .join(' · ')
}

function toggle(id: string) {
  expanded.value = expanded.value === id ? null : id
}
</script>

<template>
  <PageHead title="Campaigns" hint="Mail that arrived as one attack, grouped by what it has in common.">
    <template #actions><WindowPicker v-model="window" /></template>
  </PageHead>

  <QueryState
    :loading="q.isLoading.value"
    :error="q.error.value"
    :empty="campaigns.length === 0"
    :has-data="!!q.data.value"
    empty-text="Nothing in this window arrived more than twice in the same shape."
  >
    <p class="dim lede">
      {{ count(considered) }} messages, {{ count(grouped) }} of them in
      {{ count(campaigns.length) }} campaign{{ campaigns.length === 1 ? '' : 's' }}.
    </p>

    <div v-for="c in campaigns" :key="c.id" class="campaign">
      <button class="head" @click="toggle(c.id)">
        <span class="size">{{ c.size }}</span>
        <span class="subject">{{ short(c.subject, 80) || '(no subject)' }}</span>
        <span v-if="split(c)" class="tag unknown" title="This campaign was not judged consistently">
          split verdict
        </span>
      </button>

      <div class="meta dim">
        <span :title="iso(c.first_seen)">first {{ ago(c.first_seen) }}</span>
        ·
        <span :title="iso(c.last_seen)">last {{ ago(c.last_seen) }}</span>
        <template v-if="arr(c.senders).length">
          · {{ arr(c.senders).length }} sender{{ arr(c.senders).length === 1 ? '' : 's' }}
        </template>
        <template v-if="arr(c.link_domains).length">
          · links to <span class="mono">{{ arr(c.link_domains).slice(0, 3).join(', ') }}</span>
          <template v-if="arr(c.link_domains).length > 3">
            and {{ arr(c.link_domains).length - 3 }} more
          </template>
        </template>
        <template v-if="verdicts(c)"> · {{ verdicts(c) }}</template>
      </div>

      <table v-if="expanded === c.id" class="members">
        <thead>
          <tr><th>Received</th><th>From</th><th>Subject</th><th>Verdict</th></tr>
        </thead>
        <tbody>
          <tr v-for="m in arr(c.messages)" :key="m.message_id">
            <td :title="iso(m.received_at)">{{ ago(m.received_at) }}</td>
            <td>{{ m.sender }}</td>
            <td>
              <RouterLink :to="`/messages/${encodeURIComponent(m.message_id)}`">
                {{ short(m.subject, 60) || m.message_id }}
              </RouterLink>
            </td>
            <td><VerdictTag :verdict="m.verdict" /></td>
          </tr>
        </tbody>
      </table>
    </div>
  </QueryState>
</template>

<style scoped>
.lede { margin: 0 0 1rem; }
.campaign {
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 0.6rem 0.8rem;
  margin-bottom: 0.6rem;
}
.head {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  background: none;
  border: 0;
  padding: 0;
  width: 100%;
  text-align: left;
  cursor: pointer;
  color: inherit;
  font: inherit;
}
.size {
  min-width: 2.2rem;
  text-align: center;
  font-variant-numeric: tabular-nums;
  background: var(--panel-2);
  border-radius: 4px;
  padding: 0.1rem 0.3rem;
}
.subject { flex: 1; }
.meta { font-size: 0.82rem; margin-top: 0.3rem; }
.members { margin-top: 0.6rem; }
</style>
