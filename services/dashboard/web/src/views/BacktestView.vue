<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
/**
 * What a rule would have done, before it is allowed to do anything.
 *
 * Enabling a detection rule is a decision made blind almost everywhere: you read the
 * expression, you guess, and you find out from the complaints. Here the corpus knows
 * what arrived and what each message was told, so the rule can simply be run over the
 * last ninety days and asked.
 *
 * Three numbers come back and the third is the one that makes the other two honest:
 * matched, did not match, and could not be decided because the evidence that rule wanted
 * was never kept. Most tools fold the third into the second. That turns "we never
 * checked" into "nothing found" — and it is worse here than anywhere, because the number
 * is about to be used to make a decision.
 */
import { computed, ref } from 'vue'
import { useQuery, useMutation } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { Backtest } from '@/api/types.gen'
import { ago, arr, count, iso, short } from '@/format'
import { toast } from '@/composables/toast'
import MqlEditor from '@/components/MqlEditor.vue'
import PageHead from '@/components/PageHead.vue'
import VerdictTag from '@/components/VerdictTag.vue'

const source = ref('')
const name = ref('')
const days = ref(30)
const jobId = ref('')

const start = useMutation({
  mutationFn: () =>
    api.post<Backtest>('/backtest', { rule: source.value, name: name.value, days: days.value }),
  onSuccess: (job) => {
    // A refused rule comes back with the compiler's diagnostics rather than a job —
    // which is the whole reason to test it here instead of enabling it and waiting.
    if (job.id) jobId.value = job.id
    else result.value = job
  },
  onError: (e) => toast.err(e),
})

// Holds a refusal, which has no id to poll.
const result = ref<Backtest | null>(null)

const job = useQuery({
  queryKey: computed(() => ['backtest', jobId.value]),
  enabled: computed(() => jobId.value !== ''),
  queryFn: () => api.get<Backtest>(`/backtest/${encodeURIComponent(jobId.value)}`),
  refetchInterval: (q) => ((q.state.data as Backtest | undefined)?.state === 'running' ? 1000 : false),
})

const b = computed(() => job.data.value ?? result.value)
const running = computed(() => b.value?.state === 'running')
const missing = computed(() => Object.entries(b.value?.missing_evidence ?? {}).sort((x, y) => y[1] - x[1]))

/** Messages an analyst had already called benign. The number that stops a bad rule. */
const benign = computed(() => b.value?.benign ?? 0)
</script>

<template>
  <PageHead
    title="Backtest"
    hint="Run a proposed rule over stored mail and see what it would have caught."
  />

  <form class="stack" @submit.prevent="start.mutate()">
    <label for="name">Name (optional)</label>
    <input id="name" v-model="name" placeholder="Invoice lure, rotating sender" />

    <label for="src">Rule</label>
    <MqlEditor
      v-model="source"
      kind="rule"
      min-height="11rem"
      placeholder="type.inbound and any(body.links, .href_url.domain.root_domain in $suspicious_tlds)"
    />

    <div class="row">
      <label for="days" class="inline">Over the last</label>
      <select id="days" v-model.number="days">
        <option :value="7">7 days</option>
        <option :value="30">30 days</option>
        <option :value="90">90 days</option>
        <option :value="365">year</option>
      </select>
      <button class="primary" type="submit" :disabled="!source.trim() || start.isPending.value || running">
        {{ running ? 'Running…' : 'Run backtest' }}
      </button>
    </div>
  </form>

  <div v-if="b?.error" class="err">
    {{ b.error }}
    <pre v-if="b.diagnostics" class="detail mono">{{ b.diagnostics }}</pre>
  </div>

  <template v-if="b && !b.error">
    <div class="counts">
      <div class="stat">
        <span class="n">{{ count(b.messages_matched) }}</span>
        <span class="dim">would have fired</span>
      </div>
      <div class="stat">
        <span class="n">{{ count(b.messages_scanned - b.messages_matched - b.messages_undecided) }}</span>
        <span class="dim">would not have</span>
      </div>
      <!--
        Never folded into "would not have". A rule that could not be decided on nine
        hundred messages has not been tested on them, and saying so is the difference
        between a thin result and a clean one.
      -->
      <div class="stat" :class="{ undecided: b.messages_undecided > 0 }">
        <span class="n">{{ count(b.messages_undecided) }}</span>
        <span class="dim">could not be decided</span>
      </div>
    </div>

    <!-- .warn, not .note: base.css paints .note green, and this is a caveat. -->
    <p v-if="missing.length" class="warn small">
      Undecided because this evidence was never kept with those messages:
      <span v-for="([cap, n], i) in missing" :key="cap">
        <template v-if="i > 0">, </template>
        <span class="mono">{{ cap }}</span> ({{ count(n) }})
      </span>.
    </p>

    <p v-if="b.reviewed > 0" class="small" :class="benign > 0 ? 'warn' : 'note'">
      <template v-if="b.precision_known">
        Analysts had already judged {{ count(b.reviewed) }} of these:
        <strong>{{ Math.round(b.precision * 100) }}%</strong> of those judgements agreed with
        this rule<template v-if="benign > 0">, and {{ count(benign) }} were called benign</template>.
      </template>
      <template v-else>
        Only {{ count(b.reviewed) }} of these had already been judged — too few to say
        anything about how often this rule would be right.
      </template>
    </p>

    <template v-if="arr(b.results).length">
      <h2>Would have fired on</h2>
      <table>
        <thead>
          <tr><th>Received</th><th>From</th><th>Subject</th><th>Verdict then</th><th>Analyst said</th></tr>
        </thead>
        <tbody>
          <tr v-for="h in arr(b.results)" :key="h.message_id">
            <td :title="iso(h.received_at)">{{ ago(h.received_at) }}</td>
            <td>{{ h.sender }}</td>
            <td>
              <RouterLink :to="`/messages/${encodeURIComponent(h.message_id)}`">
                {{ short(h.subject, 60) || h.message_id }}
              </RouterLink>
            </td>
            <td><VerdictTag :verdict="h.verdict" /></td>
            <!--
              An analyst having already called this benign is the number that should
              stop the rule being enabled, so it is marked rather than listed.
            -->
            <td>
              <span v-if="h.triage" class="tag" :class="h.triage === 'benign' ? 'bad' : 'mute'">
                {{ h.triage }}
              </span>
              <span v-else class="dim">—</span>
            </td>
          </tr>
        </tbody>
      </table>
    </template>
    <p v-else-if="!running" class="dim">
      Nothing in this window would have matched.
    </p>
  </template>
</template>

<style scoped>
.inline { margin: 0; }
.counts { display: flex; gap: 2rem; margin: 1.2rem 0 0.4rem; flex-wrap: wrap; }
.stat { display: flex; flex-direction: column; }
.stat .n { font-size: 1.6rem; font-variant-numeric: tabular-nums; }
.stat.undecided .n { color: var(--unknown); }
.small { font-size: 0.88rem; max-width: 46rem; margin-top: 0.8rem; }
.detail { margin: 0.5rem 0 0; white-space: pre-wrap; }
</style>
