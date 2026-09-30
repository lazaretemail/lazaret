<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed, reactive } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { ListConfig, ListOverride } from '@/api/types.gen'
import { ago, arr, count } from '@/format'
import { useSave } from '@/composables/mutate'
import QueryState from '@/components/QueryState.vue'

const props = defineProps<{ name: string }>()

const query = useQuery({
  queryKey: computed(() => ['list', props.name]),
  queryFn: () =>
    api.get<{ list: ListConfig; overrides: ListOverride[]; sample: string[]; size: number }>(
      `/settings/lists/${encodeURIComponent(props.name)}`,
    ),
})

const list = computed(() => query.data.value?.list)
const entry = reactive({ value: '', kind: 'include', note: '' })
const key = computed(() => ['list', props.name])

const add = useSave({
  run: () => api.post(`/settings/lists/${encodeURIComponent(props.name)}/entries`, { ...entry }),
  done: 'Entry added.',
  invalidate: [key.value, ['lists']],
})
const drop = useSave({
  run: (o: ListOverride) =>
    api.del(`/settings/lists/${encodeURIComponent(props.name)}/entries`, { value: o.value, kind: o.kind, note: '' }),
  done: 'Entry removed.',
  invalidate: [key.value, ['lists']],
})
const refresh = useSave({
  run: () => api.post(`/settings/lists/${encodeURIComponent(props.name)}/refresh`),
  done: 'Refresh requested.',
  invalidate: [key.value, ['lists']],
})
</script>

<template>
  <QueryState :loading="query.isLoading.value" :error="query.error.value">
    <header class="spread">
      <div>
        <h1 class="mono">{{ props.name }}</h1>
        <p v-if="list?.description" class="dim">{{ list.description }}</p>
      </div>
      <button type="button" :disabled="refresh.isPending.value" @click="refresh.mutate()">Refresh now</button>
    </header>

    <dl class="summary panel">
      <dt>Source</dt><dd>{{ list?.source }}</dd>
      <template v-if="list?.url"><dt>URL</dt><dd class="mono break">{{ list.url }}</dd></template>
      <dt>Entries</dt><dd>{{ count(query.data.value?.size ?? 0) }}</dd>
      <dt>Last refreshed</dt><dd>{{ ago(list?.last_refresh) || 'never' }}</dd>
      <template v-if="list?.last_error"><dt>Last error</dt><dd class="bad-t">{{ list.last_error }}</dd></template>
    </dl>

    <h2>Your overrides</h2>
    <form class="row panel form" @submit.prevent="add.mutate()">
      <input v-model="entry.value" placeholder="value" required aria-label="Value" class="mono" />
      <select v-model="entry.kind" aria-label="Kind">
        <option value="include">include</option>
        <option value="exclude">exclude</option>
      </select>
      <input v-model="entry.note" placeholder="why (optional)" aria-label="Note" class="grow" />
      <button class="primary" type="submit" :disabled="add.isPending.value">Add</button>
    </form>

    <table v-if="arr(query.data.value?.overrides).length">
      <thead><tr><th>Value</th><th>Kind</th><th>Note</th><th>Added</th><th></th></tr></thead>
      <tbody>
        <tr v-for="o in arr(query.data.value?.overrides)" :key="`${o.kind}:${o.value}`">
          <td class="mono">{{ o.value }}</td>
          <td><span class="tag" :class="o.kind === 'exclude' ? 'unknown' : 'act'">{{ o.kind }}</span></td>
          <td class="dim">{{ o.note }}</td>
          <td class="dim nowrap">{{ ago(o.added_at) }}<template v-if="o.added_by"> · {{ o.added_by }}</template></td>
          <td class="right"><button class="link danger-link" type="button" @click="drop.mutate(o)">remove</button></td>
        </tr>
      </tbody>
    </table>
    <p v-else class="dim">No override. This list is exactly what its source says.</p>

    <template v-if="arr(query.data.value?.sample).length">
      <h2>Sample of entries</h2>
      <div class="sample mono">
        <span v-for="s in arr(query.data.value?.sample)" :key="s">{{ s }}</span>
      </div>
    </template>
  </QueryState>
</template>

<style scoped>
.form { margin-bottom: 1rem; gap: .5rem; }
.break { overflow-wrap: anywhere; }
.bad-t { color: var(--bad); }
.danger-link { color: var(--bad); }
.sample { display: flex; flex-wrap: wrap; gap: .25rem .75rem; font-size: .84rem; color: var(--dim); }
</style>
