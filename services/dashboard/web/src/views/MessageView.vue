<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { MessagePage } from '@/api/types.gen'
import QueryState from '@/components/QueryState.vue'
import MessageDetail from '@/components/MessageDetail.vue'

const props = defineProps<{ id: string }>()

const query = useQuery({
  queryKey: computed(() => ['message', props.id]),
  queryFn: () => api.get<MessagePage>(`/messages/${encodeURIComponent(props.id)}`),
})
</script>

<template>
  <QueryState :loading="query.isLoading.value" :error="query.error.value">
    <MessageDetail v-if="query.data.value" :page="query.data.value" />
  </QueryState>
</template>
