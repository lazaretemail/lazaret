<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { ref, watch } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { OrgConfig } from '@/api/types.gen'
import { arr } from '@/format'
import { useSave } from '@/composables/mutate'
import PageHead from '@/components/PageHead.vue'
import QueryState from '@/components/QueryState.vue'

const query = useQuery({ queryKey: ['org'], queryFn: () => api.get<OrgConfig>('/settings/org') })

// Edited as text, because a textarea of one-per-line is the fastest way to paste a
// domain list out of wherever it currently lives.
const domains = ref('')
const displayNames = ref('')
const vips = ref('')

watch(
  () => query.data.value,
  (o) => {
    if (!o) return
    domains.value = arr(o.domains).join('\n')
    displayNames.value = arr(o.display_names).join('\n')
    vips.value = arr(o.vips).map((v) => `${v.email}${v.display_name ? ` ${v.display_name}` : ''}`).join('\n')
  },
  { immediate: true },
)

const lines = (s: string) => s.split('\n').map((l) => l.trim()).filter(Boolean)

const save = useSave({
  run: () =>
    api.put('/settings/org', {
      domains: lines(domains.value),
      display_names: lines(displayNames.value),
      vips: lines(vips.value).map((l) => {
        const [email, ...rest] = l.split(/\s+/)
        return { email: email ?? '', display_name: rest.join(' ') }
      }),
    } satisfies OrgConfig),
  done: 'Organisation saved.',
  invalidate: [['org'], ['coverage']],
})
</script>

<template>
  <PageHead
    title="Organisation"
    hint="Which domains are yours. This decides what counts as inbound, and it gates most of the rule set."
  />

  <QueryState :loading="query.isLoading.value" :error="query.error.value">
    <form class="stack panel" @submit.prevent="save.mutate()">
      <div>
        <label for="d">Verified domains — one per line</label>
        <textarea id="d" v-model="domains" rows="6" spellcheck="false" />
      </div>
      <div>
        <label for="v">VIPs — <code>email Display Name</code>, one per line</label>
        <textarea id="v" v-model="vips" rows="5" spellcheck="false" />
      </div>
      <div>
        <label for="n">Display names to protect from impersonation — one per line</label>
        <textarea id="n" v-model="displayNames" rows="4" spellcheck="false" />
      </div>
      <div class="row">
        <button class="primary" type="submit" :disabled="save.isPending.value">Save</button>
      </div>
    </form>
  </QueryState>
</template>

<style scoped>
code { font-family: var(--mono); font-size: .9em; }
</style>
