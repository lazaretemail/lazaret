<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
/**
 * What we learned about mail after it was delivered.
 *
 * Two things put a row here, and they are the same kind of thing: intelligence that
 * arrived after the verdict did. A feed added a rule this afternoon that matches a
 * message from Tuesday; a link that served a holding page on Tuesday now serves a
 * credential form.
 *
 * Nothing on this page has acted. That is deliberate and it is stated on the page,
 * because a list of things a system found is read very differently depending on whether
 * it also did something about them. Acting is a step the analyst takes on the message
 * itself, exactly as they would have on the day.
 */
import { computed, ref } from 'vue'
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { Findings, Finding } from '@/api/types.gen'
import { ago, arr, count, iso, short } from '@/format'
import { toast } from '@/composables/toast'
import PageHead from '@/components/PageHead.vue'
import QueryState from '@/components/QueryState.vue'

const state = ref<'new' | 'all'>('new')
const qc = useQueryClient()

const q = useQuery({
  queryKey: computed(() => ['findings', state.value]),
  queryFn: () => api.get<Findings>('/findings', { state: state.value }),
})

const findings = computed(() => arr(q.data.value?.findings))
const watched = computed(() => q.data.value?.links_watched ?? 0)
const sweeping = computed(() => q.data.value?.sweeping ?? false)
const windowDays = computed(() => q.data.value?.window_days ?? 0)

const resolve = useMutation({
  mutationFn: (v: { id: string; state: string }) =>
    api.post(`/findings/${encodeURIComponent(v.id)}/resolve`, { state: v.state }),
  onSuccess: () => {
    qc.invalidateQueries({ queryKey: ['findings'] })
    // The sidebar badge is part of the session bootstrap, so it has to be told too.
    qc.invalidateQueries({ queryKey: ['session'] })
  },
  onError: (e) => toast.err(e),
})

function kindLabel(f: Finding): string {
  return f.kind === 'link' ? 'Link changed' : 'New detection'
}
</script>

<template>
  <PageHead
    title="Found later"
    hint="Mail that had already been delivered when we learned something about it. Nothing here has been acted on."
  >
    <template #actions>
      <select v-model="state" aria-label="Which findings">
        <option value="new">Open</option>
        <option value="all">Everything</option>
      </select>
    </template>
  </PageHead>

  <QueryState
    :loading="q.isLoading.value"
    :error="q.error.value"
    :empty="findings.length === 0"
    :has-data="!!q.data.value"
    :empty-text="
      state === 'new'
        ? 'Nothing has turned up about delivered mail.'
        : 'No findings have ever been filed.'
    "
  >
    <table>
      <thead>
        <tr>
          <th>What</th>
          <th>Message</th>
          <th>Found</th>
          <th class="right">Decide</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="f in findings" :key="f.id" :class="{ done: f.state !== 'new' }">
          <td>
            <span class="tag" :class="f.kind === 'link' ? 'unknown' : 'act'">{{ kindLabel(f) }}</span>
            <div class="mono src">{{ short(f.source, 90) }}</div>
            <div v-if="f.detail" class="dim detail">{{ f.detail }}</div>
          </td>
          <td>
            <RouterLink :to="`/messages/${encodeURIComponent(f.message_id)}`">
              {{ f.subject || f.message_id }}
            </RouterLink>
            <div v-if="f.sender" class="dim">{{ f.sender }}</div>
          </td>
          <td :title="iso(f.found_at)">
            {{ ago(f.found_at) }}
            <div v-if="f.state !== 'new'" class="dim">
              {{ f.state }}<template v-if="f.reviewed_by"> · {{ f.reviewed_by }}</template>
            </div>
          </td>
          <td class="right">
            <template v-if="f.state === 'new'">
              <button
                class="small"
                :disabled="resolve.isPending.value"
                @click="resolve.mutate({ id: f.id, state: 'actioned' })"
              >
                Real
              </button>
              <button
                class="small"
                :disabled="resolve.isPending.value"
                @click="resolve.mutate({ id: f.id, state: 'dismissed' })"
              >
                Not a problem
              </button>
            </template>
          </td>
        </tr>
      </tbody>
    </table>
  </QueryState>

  <!--
    Said whether or not there are findings. An empty list means two opposite things
    depending on these: nothing has turned up, or nothing is looking.
  -->
  <p class="dim foot">
    <template v-if="sweeping">
      New detection content and list updates are checked against the last
      {{ windowDays }} days of mail.
    </template>
    <template v-else>
      Delivered mail is not re-checked when new detection content arrives. Turn it on
      with <span class="mono">-retro-sweep</span>.
    </template>
    <br />
    <template v-if="watched > 0">
      {{ count(watched) }} link{{ watched === 1 ? '' : 's' }} from delivered mail are still
      scheduled to be looked at again.
    </template>
    <template v-else>
      No links are scheduled for a second look. Re-visiting needs the renderer, link
      analysis, and <span class="mono">-link-watch</span>.
    </template>
  </p>
</template>

<style scoped>
.small { font-size: .8rem; padding: .2rem .5rem; }
.src { font-size: 0.82rem; margin-top: 0.2rem; }
.detail { font-size: 0.82rem; margin-top: 0.15rem; max-width: 42rem; }
.right { text-align: right; white-space: nowrap; }
tr.done { opacity: 0.6; }
.foot { margin-top: 1rem; font-size: 0.85rem; }
</style>
