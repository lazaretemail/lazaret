<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { Insights, Capabilities } from '@/api/types.gen'
import { arr, count } from '@/format'
import PageHead from '@/components/PageHead.vue'
import QueryState from '@/components/QueryState.vue'
import WindowPicker from '@/components/WindowPicker.vue'
import { useUrlWindow } from '@/composables/window'

const window = useUrlWindow()
const query = useQuery({
  queryKey: computed(() => ['overview', window.value]),
  queryFn: () => api.get<{ insights: Insights; capabilities: Capabilities | null }>('/overview', { window: window.value }),
  placeholderData: (p) => p,
})

const ins = computed(() => query.data.value?.insights)
const caps = computed(() => query.data.value?.capabilities)
const days = computed(() => arr(ins.value?.by_day))
const peak = computed(() => Math.max(1, ...days.value.map((d) => d.malicious + d.indeterminate + d.clean)))

// The engine reports one count per verdict; the total is their sum rather than a
// separate field, so it cannot disagree with the three numbers beside it.
const totals = computed(() => {
  const t = ins.value?.totals ?? {}
  const n = (k: string) => Number(t[k] ?? 0)
  return [
    ['Messages', n('malicious') + n('indeterminate') + n('clean'), ''],
    ['Malicious', n('malicious'), 'bad-n'],
    ['Indeterminate', n('indeterminate'), 'unk-n'],
    ['Clean', n('clean'), ''],
  ] as [string, number, string][]
})

// Running on the CPU when GPU providers were offered and turned down is a different
// thing from having no GPU: it means somebody meant this deployment to have one. That
// is the shape worth warning about, and it is exactly what happened here — the
// accelerator overlay was left off a deploy and 372 rules quietly went unanswerable.
const cpuFallback = computed(() => {
  const inf = caps.value?.inference
  return !!inf && inf.provider === 'cpu' && arr(inf.tried).length > 0
})
</script>

<template>
  <PageHead title="Overview" hint="What has been arriving, and what the engine could and could not answer.">
    <template #actions><WindowPicker v-model="window" /></template>
  </PageHead>

  <QueryState :loading="query.isLoading.value" :error="query.error.value" :has-data="!!query.data.value">
    <div class="cards">
      <div v-for="[label, n, cls] in totals" :key="label" class="panel card">
        <div class="n" :class="cls">{{ count(n) }}</div>
        <div class="dim">{{ label }}</div>
      </div>
    </div>

    <h2>By day</h2>
    <div v-if="!days.length" class="empty">Nothing in this window.</div>
    <div v-else class="chart" role="img" aria-label="Messages by day and verdict">
      <div v-for="d in days" :key="d.day" class="col" :title="`${d.day}: ${d.malicious} malicious, ${d.indeterminate} indeterminate, ${d.clean} clean`">
        <div class="stack2">
          <div class="seg bad" :style="{ height: `${(d.malicious / peak) * 100}%` }" />
          <div class="seg unk" :style="{ height: `${(d.indeterminate / peak) * 100}%` }" />
          <div class="seg ok" :style="{ height: `${(d.clean / peak) * 100}%` }" />
        </div>
      </div>
    </div>

    <div class="two">
      <section>
        <h2>Rules firing most</h2>
        <table v-if="arr(ins?.top_rules).length">
          <tbody>
            <tr v-for="r in arr(ins?.top_rules)" :key="r.name">
              <td>{{ r.name }}</td>
              <td class="right mono">{{ count(r.count) }}</td>
            </tr>
          </tbody>
        </table>
        <p v-else class="dim">No rule has fired in this window.</p>
      </section>

      <section>
        <h2>Capabilities unavailable</h2>
        <p v-if="!arr(ins?.missing_capabilities).length" class="dim">
          Every capability the rule set asks for answered.
        </p>
        <table v-else>
          <tbody>
            <tr v-for="m in arr(ins?.missing_capabilities)" :key="m.name">
              <td class="mono">{{ m.name }}</td>
              <td class="right dim">{{ count(m.count) }} messages affected</td>
            </tr>
          </tbody>
        </table>
        <p v-if="caps && caps.rules_unanswerable > 0" class="warn">
          {{ count(caps.rules_unanswerable) }} of {{ count(caps.rules_loaded) }} rules cannot be
          fully evaluated right now.
        </p>
        <p v-if="cpuFallback" class="warn">
          Inference is running on the CPU, and {{ arr(caps?.inference?.tried).join(', ') }}
          {{ arr(caps?.inference?.tried).length === 1 ? 'was' : 'were' }} offered and refused by
          the runtime. The classifier is the slowest part of an analysis by a wide margin — under
          load it has been measured at 82s against a 120s budget — so this is the usual reason
          rules go unanswered. Check that the accelerator overlay is deployed and that the
          container has the GPU devices.
        </p>
      </section>
    </div>
  </QueryState>
</template>

<style scoped>
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr)); gap: .75rem; }
.card .n { font-size: 1.6rem; font-weight: 600; font-variant-numeric: tabular-nums; }
.bad-n { color: var(--bad); }
.unk-n { color: var(--unknown); }
.chart { display: flex; gap: 2px; align-items: flex-end; height: 9rem; padding: .5rem; background: var(--panel); border: 1px solid var(--line); border-radius: var(--r); }
.col { flex: 1; height: 100%; display: flex; align-items: flex-end; min-width: 2px; }
.stack2 { width: 100%; height: 100%; display: flex; flex-direction: column; justify-content: flex-end; }
.seg.bad { background: var(--bad); }
.seg.unk { background: var(--unknown); }
.seg.ok { background: color-mix(in srgb, var(--ok) 55%, transparent); }
.two { display: grid; grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr)); gap: 2rem; }
</style>
