<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { ListConfig } from '@/api/types.gen'
import { ago, arr, count } from '@/format'
import PageHead from '@/components/PageHead.vue'
import QueryState from '@/components/QueryState.vue'

const query = useQuery({
  queryKey: ['lists'],
  queryFn: () => api.get<{ lists: ListConfig[]; available: string[] }>('/settings/lists'),
})
const lists = computed(() => arr(query.data.value?.lists))
</script>

<template>
  <PageHead title="Lists" hint="The named sets rules match against — free mail providers, shorteners, your own allowlists." />

  <QueryState
    :loading="query.isLoading.value"
    :error="query.error.value"
    :empty="lists.length === 0"
    empty-text="No list is configured."
  >
    <table>
      <thead>
        <tr><th>Name</th><th>Source</th><th class="right">Entries</th><th class="right">Rules using</th><th>Refreshed</th><th>State</th></tr>
      </thead>
      <tbody>
        <tr v-for="l in lists" :key="l.name">
          <td><RouterLink :to="`/settings/lists/${encodeURIComponent(l.name)}`" class="mono">{{ l.name }}</RouterLink></td>
          <td class="dim">{{ l.source }}</td>
          <td class="right mono">{{ count(l.entry_count) }}</td>
          <td class="right mono">{{ count(l.rules_using) }}</td>
          <td class="dim nowrap">{{ ago(l.last_refresh) }}</td>
          <td>
            <span class="tag" :class="l.enabled ? 'ok' : 'mute'">{{ l.enabled ? 'enabled' : 'disabled' }}</span>
            <div v-if="l.last_error" class="tiny bad-t">{{ l.last_error }}</div>
          </td>
        </tr>
      </tbody>
    </table>
  </QueryState>
</template>

<style scoped>
.tiny { font-size: .78rem; }
.bad-t { color: var(--bad); }
</style>
