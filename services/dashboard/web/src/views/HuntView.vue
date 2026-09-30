<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed, ref } from 'vue'
import { useQuery, useMutation } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { HuntJob } from '@/api/types.gen'
import { arr, count } from '@/format'
import { toast } from '@/composables/toast'
import MqlEditor from '@/components/MqlEditor.vue'
import PageHead from '@/components/PageHead.vue'
import WindowPicker from '@/components/WindowPicker.vue'

const source = ref('')
const window = ref('30')
const jobId = ref('')

// ---- running ------------------------------------------------------------

const start = useMutation({
  mutationFn: () => api.post<HuntJob>('/hunt', { source: source.value, window: window.value }),
  onSuccess: (job) => {
    jobId.value = job.id
  },
  onError: (e) => toast.err(e),
})

const job = useQuery({
  queryKey: computed(() => ['hunt', jobId.value]),
  enabled: computed(() => jobId.value !== ''),
  queryFn: () => api.get<HuntJob>(`/hunt/${encodeURIComponent(jobId.value)}`),
  // Poll only while it is actually running.
  refetchInterval: (q) => {
    const s = (q.state.data as HuntJob | undefined)?.state
    return s && s !== 'done' && s !== 'failed' ? 1500 : false
  },
})

const j = computed(() => job.data.value)
const running = computed(() => !!j.value && j.value.state !== 'done' && j.value.state !== 'failed')

// What the hunt could not decide, and why.
//
// A hunt replays the enrichment answers frozen beside each message. A question a
// message was never asked comes back unavailable, not null, so the expression reports
// indeterminate and the hunt counts it here instead of as a clean no-match. Showing it
// is the difference between "nothing matched" and "we could not check 900 of these".
const undecided = computed(() => j.value?.messages_undecided ?? 0)
const missing = computed(() =>
  Object.entries(j.value?.missing_evidence ?? {}).sort((a, b) => b[1] - a[1]),
)
</script>

<template>
  <PageHead title="Hunt" hint="Run an MQL expression across stored mail.">
    <template #actions><WindowPicker v-model="window" /></template>
  </PageHead>

  <form class="stack" @submit.prevent="start.mutate()">
    <label for="src">Expression</label>
    <MqlEditor
      v-model="source"
      kind="query"
      min-height="11rem"
      placeholder="any(body.links, .href_url.domain.root_domain == 'example.com')"
    />

    <div class="row">
      <button class="primary" type="submit" :disabled="!source.trim() || start.isPending.value || running">
        {{ running ? 'Hunting…' : 'Run hunt' }}
      </button>
      <span v-if="j" class="dim">
        {{ j.state }} · {{ count(j.messages_scanned) }} scanned · {{ count(j.messages_matched) }} matched
        <template v-if="undecided > 0"> · {{ count(undecided) }} undecided</template>
      </span>
    </div>
  </form>

  <div v-if="j?.error" class="err">{{ j.error }}</div>

  <!--
    Never folded into "did not match". Turning "we never checked" into "nothing found"
    is the one answer a hunt must not give silently, and it is exactly the answer
    somebody is about to act on.
  -->
  <p v-if="undecided > 0" class="warn caveat">
    {{ count(undecided) }} message{{ undecided === 1 ? '' : 's' }} could not be decided:
    the expression needed evidence that was never kept with them.
    <template v-if="missing.length">
      Missing
      <span v-for="([cap, n], i) in missing" :key="cap">
        <template v-if="i > 0">, </template>
        <span class="mono">{{ cap }}</span> ({{ count(n) }})
      </span>.
    </template>
  </p>

  <template v-if="j && arr(j.results).length">
    <h2>Matches</h2>
    <table>
      <thead><tr><th>Message</th></tr></thead>
      <tbody>
        <tr v-for="r in arr(j.results)" :key="r.message_id">
          <td><RouterLink :to="`/messages/${encodeURIComponent(r.message_id)}`" class="mono">{{ r.message_id }}</RouterLink></td>
        </tr>
      </tbody>
    </table>
  </template>
  <p v-else-if="j && !running" class="dim">Nothing matched.</p>
</template>

<style scoped>
.caveat { font-size: .88rem; max-width: 46rem; }
</style>
