<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { ModelReport } from '@/api/types.gen'
import { arr, count, stamp } from '@/format'
import { useSave } from '@/composables/mutate'
import PageHead from '@/components/PageHead.vue'
import QueryState from '@/components/QueryState.vue'

const query = useQuery({ queryKey: ['model'], queryFn: () => api.get<ModelReport>('/settings/learning') })
const m = computed(() => query.data.value)

const train = useSave({
  run: () => api.post('/settings/learning/train'),
  done: 'Training started.',
  invalidate: [['model']],
})
const forget = useSave({
  run: () => api.del('/settings/learning'),
  done: 'Model discarded.',
  invalidate: [['model']],
})

function discard() {
  if (confirm('Discard the trained model? Scoring falls back to rules alone until it is retrained.')) {
    forget.mutate()
  }
}

const pct = (n?: number) => (n === undefined ? '—' : `${Math.round(n * 100)}%`)
</script>

<template>
  <PageHead
    title="Learning"
    hint="A model trained on this deployment's own triage decisions. Advisory — it never overrides a rule."
  >
    <template #actions>
      <button class="primary" type="button" :disabled="train.isPending.value" @click="train.mutate()">Train now</button>
      <button v-if="m?.trained" class="danger" type="button" @click="discard">Discard</button>
    </template>
  </PageHead>

  <QueryState :loading="query.isLoading.value" :error="query.error.value">
    <div v-if="!m?.trained" class="note">
      No model yet. It needs {{ count(m?.need_total ?? 0) }} reviewed messages
      (at least {{ count(m?.need_per_side ?? 0) }} of each judgement) before training is worth doing —
      a model fitted on less would mostly be repeating the rules back.
    </div>

    <dl class="summary panel">
      <dt>Trained</dt>
      <dd>
        <template v-if="m?.trained">version {{ m.version }}, {{ stamp(m.trained_at) }}</template>
        <template v-else>not yet</template>
      </dd>
      <dt>Useful</dt>
      <dd>
        <span class="tag" :class="m?.useful ? 'ok' : 'mute'">{{ m?.useful ? 'better than guessing' : 'not yet' }}</span>
      </dd>
      <dt>Accuracy</dt><dd>{{ pct(m?.accuracy) }} <span class="dim">(baseline {{ pct(m?.baseline) }})</span></dd>
      <dt>Learned from</dt>
      <dd>{{ count(m?.reviews ?? 0) }} reviews — {{ count(m?.confirmed ?? 0) }} confirmed, {{ count(m?.dismissed ?? 0) }} dismissed</dd>
    </dl>

    <template v-if="arr(m?.top).length">
      <h2>What it keys on</h2>
      <table>
        <thead><tr><th>Feature</th><th>Points toward</th><th class="right">Weight</th></tr></thead>
        <tbody>
          <tr v-for="c in arr(m?.top)" :key="c.feature">
            <td class="mono">{{ c.feature }}</td>
            <td :class="c.toward === 'malicious' ? 'bad-t' : 'ok-t'">{{ c.toward }}</td>
            <td class="right mono">{{ c.weight.toFixed(3) }}</td>
          </tr>
        </tbody>
      </table>
    </template>
  </QueryState>
</template>

<style scoped>
.bad-t { color: var(--bad); }
.ok-t { color: var(--ok); }
.note { margin-bottom: 1rem; }
</style>
