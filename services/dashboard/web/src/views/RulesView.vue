<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed, ref } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { Rule, Capabilities } from '@/api/types.gen'
import { arr, count } from '@/format'
import PageHead from '@/components/PageHead.vue'
import QueryState from '@/components/QueryState.vue'

const filter = ref('')
const onlyBlocked = ref(false)

const query = useQuery({
  queryKey: ['detections'],
  queryFn: () => api.get<{ rules: Rule[]; capabilities: Capabilities | null }>('/detections'),
})

const caps = computed(() => query.data.value?.capabilities)

// A capability is "down" if the engine reports it unhealthy; a rule needing one is
// loaded but cannot answer, which is a different thing from being disabled.
const down = computed(() => {
  const set = new Set<string>()
  for (const c of arr(caps.value?.capability_health)) {
    if (!c.ok) set.add(c.capability)
  }
  return set
})

function blocked(r: Rule): string[] {
  return arr(r.needs).filter((n) => down.value.has(n)) as string[]
}

const rules = computed(() => {
  const needle = filter.value.trim().toLowerCase()
  return arr(query.data.value?.rules).filter((r) => {
    if (onlyBlocked.value && blocked(r).length === 0) return false
    if (!needle) return true
    return r.name.toLowerCase().includes(needle) || r.id.toLowerCase().includes(needle)
  })
})
</script>

<template>
  <PageHead title="Rules" :hint="caps ? `${count(caps.rules_loaded)} loaded, ${count(caps.rules_unanswerable)} cannot be fully answered right now` : undefined">
    <template #actions>
      <input v-model="filter" type="search" placeholder="Filter rules…" aria-label="Filter rules" style="min-width: 16rem" />
      <label class="inline"><input v-model="onlyBlocked" type="checkbox" /> only blocked</label>
    </template>
  </PageHead>

  <QueryState
    :loading="query.isLoading.value"
    :error="query.error.value"
    :empty="rules.length === 0"
    empty-text="No rule matches."
  >
    <table>
      <thead><tr><th>Name</th><th>Type</th><th>Severity</th><th>Needs</th></tr></thead>
      <tbody>
        <tr v-for="r in rules" :key="r.id">
          <td><RouterLink :to="`/detections/${encodeURIComponent(r.id)}`">{{ r.name }}</RouterLink></td>
          <td class="dim">{{ r.type }}</td>
          <td :class="`sev-${r.severity}`">{{ r.severity }}</td>
          <td>
            <span v-for="n in arr(r.needs)" :key="n" class="tag" :class="down.has(n) ? 'bad' : 'mute'" :title="down.has(n) ? 'unavailable right now' : ''">
              {{ n }}
            </span>
          </td>
        </tr>
      </tbody>
    </table>
  </QueryState>
</template>

<style scoped>
.inline { display: inline-flex; align-items: center; gap: .35rem; margin: 0; }
td .tag { margin: 0 .2rem .2rem 0; }
</style>
