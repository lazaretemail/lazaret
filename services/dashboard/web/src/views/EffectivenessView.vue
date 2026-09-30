<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { Effectiveness } from '@/api/types.gen'
import { arr, count } from '@/format'
import PageHead from '@/components/PageHead.vue'
import QueryState from '@/components/QueryState.vue'
import WindowPicker from '@/components/WindowPicker.vue'
import { useUrlWindow } from '@/composables/window'

const window = useUrlWindow()
const query = useQuery({
  queryKey: computed(() => ['effectiveness', window.value]),
  queryFn: () => api.get<Effectiveness>('/detections/effectiveness', { window: window.value }),
  placeholderData: (p) => p,
})

const rows = computed(() =>
  [...arr(query.data.value?.rules)].sort((a, b) => Number(b.fired) - Number(a.fired)),
)

/** A rule that fires often and is confirmed rarely is the definition of noise. */
function precision(r: { fired: number; confirmed: number }): string {
  const reviewed = Number(r.fired)
  if (!reviewed) return '—'
  return `${Math.round((Number(r.confirmed) / reviewed) * 100)}%`
}
</script>

<template>
  <PageHead title="Effectiveness" hint="Which rules earn their place, and which only make noise.">
    <template #actions><WindowPicker v-model="window" /></template>
  </PageHead>

  <QueryState :loading="query.isLoading.value" :error="query.error.value" :has-data="!!query.data.value">
    <p class="dim">
      {{ count(query.data.value?.dormant_count ?? 0) }} of {{ count(query.data.value?.loaded ?? 0) }}
      rules did not fire at all in this window.
    </p>

    <table v-if="rows.length">
      <thead>
        <tr>
          <th>Rule</th><th class="right">Fired</th><th class="right">Confirmed</th>
          <th class="right">Benign</th><th class="right">Unreviewed</th><th class="right">Confirmed rate</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="r in rows" :key="r.rule">
          <td>{{ r.rule }}</td>
          <td class="right mono">{{ count(r.fired) }}</td>
          <td class="right mono">{{ count(r.confirmed) }}</td>
          <td class="right mono">{{ count(r.benign) }}</td>
          <td class="right mono dim">{{ count(r.unreviewed) }}</td>
          <td class="right mono">{{ precision(r) }}</td>
        </tr>
      </tbody>
    </table>
    <p v-else class="empty">No rule fired in this window.</p>

    <template v-if="arr(query.data.value?.dormant).length">
      <h2>Dormant</h2>
      <p class="dim tiny">Loaded and answerable, but nothing matched them.</p>
      <div class="dormant">
        <span v-for="d in arr(query.data.value?.dormant)" :key="d" class="tag mute">{{ d }}</span>
      </div>
    </template>
  </QueryState>
</template>

<style scoped>
.dormant { display: flex; flex-wrap: wrap; gap: .3rem; }
.tiny { font-size: .82rem; }
</style>
