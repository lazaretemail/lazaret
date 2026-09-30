<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { ConfiguredAction } from '@/api/types.gen'
import { arr } from '@/format'
import MqlEditor from '@/components/MqlEditor.vue'
import QueryState from '@/components/QueryState.vue'

const props = defineProps<{ id: string }>()

const query = useQuery({
  queryKey: computed(() => ['rule', props.id]),
  queryFn: () => api.get<{ rule: Record<string, unknown>; actions: ConfiguredAction[] | null }>(`/detections/${encodeURIComponent(props.id)}`),
})

const rule = computed(() => query.data.value?.rule ?? {})
const str = (k: string) => (typeof rule.value[k] === 'string' ? (rule.value[k] as string) : '')
</script>

<template>
  <QueryState :loading="query.isLoading.value" :error="query.error.value">
    <h1>{{ str('name') || props.id }}</h1>
    <p v-if="str('description')" class="dim">{{ str('description') }}</p>

    <dl class="summary panel">
      <dt>Identifier</dt><dd class="mono">{{ props.id }}</dd>
      <template v-if="str('type')"><dt>Type</dt><dd>{{ str('type') }}</dd></template>
      <template v-if="str('severity')"><dt>Severity</dt><dd :class="`sev-${str('severity')}`">{{ str('severity') }}</dd></template>
    </dl>

    <h2>Actions attached</h2>
    <p v-if="!arr(query.data.value?.actions).length" class="dim">
      None. Messages this rule flags are queued for review rather than acted on.
    </p>
    <ul v-else>
      <li v-for="a in arr(query.data.value?.actions)" :key="a.id">
        {{ a.label }} <span class="tag act">{{ a.type }}</span>
        <span v-if="!a.enabled" class="tag mute">disabled</span>
      </li>
    </ul>

    <h2>Source</h2>
    <MqlEditor :model-value="str('source')" kind="rule" min-height="6rem" />
  </QueryState>
</template>

<style scoped>
.src { background: var(--panel); border: 1px solid var(--line); border-radius: var(--r); padding: .8rem; overflow: auto; font-size: .84rem; }
</style>
