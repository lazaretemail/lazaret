<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { Coverage } from '@/api/types.gen'
import { arr, count } from '@/format'
import PageHead from '@/components/PageHead.vue'
import QueryState from '@/components/QueryState.vue'

const query = useQuery({ queryKey: ['coverage'], queryFn: () => api.get<Coverage>('/detections/coverage') })
const c = computed(() => query.data.value)
</script>

<template>
  <PageHead title="Coverage" hint="What the rule set asks for, and what this deployment can actually answer." />

  <QueryState :loading="query.isLoading.value" :error="query.error.value">
    <div class="cards">
      <div class="panel card"><div class="n">{{ count(c?.loaded ?? 0) }}</div><div class="dim">Rules loaded</div></div>
      <div class="panel card"><div class="n ok-n">{{ count(c?.fully_answerable ?? 0) }}</div><div class="dim">Fully answerable</div></div>
      <div class="panel card"><div class="n" :class="{ 'bad-n': (c?.blocked ?? 0) > 0 }">{{ count(c?.blocked ?? 0) }}</div><div class="dim">Blocked</div></div>
    </div>

    <h2>Capabilities</h2>
    <table>
      <thead><tr><th>Capability</th><th class="right">Rules using it</th><th>State</th></tr></thead>
      <tbody>
        <tr v-for="cap in arr(c?.capabilities)" :key="cap.capability">
          <td class="mono">{{ cap.capability }}</td>
          <td class="right mono">{{ count(cap.rules) }}</td>
          <td><span class="tag" :class="cap.available ? 'ok' : 'bad'">{{ cap.available ? 'available' : 'unavailable' }}</span></td>
        </tr>
      </tbody>
    </table>

    <template v-if="arr(c?.lists_unavailable).length">
      <h2>Lists unavailable</h2>
      <div class="row">
        <span v-for="l in arr(c?.lists_unavailable)" :key="l" class="tag unknown">{{ l }}</span>
      </div>
    </template>
  </QueryState>
</template>

<style scoped>
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr)); gap: .75rem; margin-bottom: 1rem; }
.card .n { font-size: 1.6rem; font-weight: 600; font-variant-numeric: tabular-nums; }
.ok-n { color: var(--ok); }
.bad-n { color: var(--bad); }
</style>
