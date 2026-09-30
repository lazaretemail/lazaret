<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { RuleFeed } from '@/api/types.gen'
import { ago, arr, count, stamp } from '@/format'
import { useSave } from '@/composables/mutate'
import { toast } from '@/composables/toast'
import PageHead from '@/components/PageHead.vue'
import QueryState from '@/components/QueryState.vue'

const query = useQuery({
  queryKey: ['feeds'],
  queryFn: () => api.get<{ feeds: RuleFeed[] }>('/settings/feeds'),
  // A sync in progress changes rule counts under the page.
  refetchInterval: 30_000,
})
const feeds = computed(() => arr(query.data.value?.feeds))

const editing = ref(false)
const form = reactive<{ id: string; name: string; url: string; branch: string; subdir: string; enabled: boolean; every_seconds: number; secret: string }>({
  id: '', name: '', url: '', branch: '', subdir: '', enabled: true, every_seconds: 21600, secret: '',
})

function open(f?: RuleFeed) {
  editing.value = true
  form.id = f?.id ?? ''
  form.name = f?.name ?? ''
  form.url = f?.url ?? ''
  form.branch = f?.branch ?? ''
  form.subdir = f?.subdir ?? ''
  form.enabled = f?.enabled ?? true
  form.every_seconds = f?.every_seconds ?? 21600
  form.secret = ''
}

const invalidate = [['feeds'], ['detections'], ['session']]

const save = useSave({
  run: () => api.post('/settings/feeds', { ...form, has_secret: false, rule_count: 0, created_at: '' }),
  done: 'Feed saved.',
  invalidate,
})
const remove = useSave({
  run: (id: string) => api.del(`/settings/feeds/${encodeURIComponent(id)}`),
  done: 'Feed removed. The rules it supplied are no longer loaded.',
  invalidate,
})

// Sync answers 200 even when the pull failed, because the request succeeded and the
// pull did not — the page has to tell those apart rather than show one error box.
const syncing = ref('')
async function syncNow(f: RuleFeed) {
  syncing.value = f.id
  try {
    const out = await api.post<{ ok: boolean; error?: string; rules_loaded?: number; reload_error?: string }>(
      `/settings/feeds/${encodeURIComponent(f.id)}/sync`,
    )
    if (!out.ok) toast.err(out.error ?? 'the pull failed')
    else if (out.reload_error) toast.err(`pulled, but the rules did not reload: ${out.reload_error}`)
    else toast.ok(`${f.name} synced — ${count(out.rules_loaded ?? 0)} rules loaded`)
  } catch (e) {
    toast.err(e)
  } finally {
    syncing.value = ''
    query.refetch()
  }
}

function submit() {
  save.mutate()
  editing.value = false
}

function removeFeed(f: RuleFeed) {
  if (confirm(`Remove "${f.name}"? The ${count(f.rule_count)} rules it supplies stop being loaded.`)) {
    remove.mutate(f.id)
  }
}

const EVERY: [number, string][] = [
  [900, 'every 15 minutes'],
  [3600, 'hourly'],
  [21600, 'every 6 hours'],
  [86400, 'daily'],
  [604800, 'weekly'],
]
</script>

<template>
  <PageHead
    title="Rule feeds"
    hint="Where detection content comes from. Each feed is a git repository, cloned on a schedule."
  >
    <template #actions>
      <button class="primary" type="button" @click="open()">Add feed</button>
    </template>
  </PageHead>

  <form v-if="editing" class="panel stack edit" @submit.prevent="submit">
    <div class="grid">
      <div><label for="n">Name</label><input id="n" v-model="form.name" required placeholder="Our team's rules" /></div>
      <div>
        <label for="u">Repository URL</label>
        <input id="u" v-model="form.url" required class="mono" placeholder="https://github.com/org/repo" />
      </div>
      <div><label for="b">Branch</label><input id="b" v-model="form.branch" placeholder="default" /></div>
      <div>
        <label for="s">Path within the repository</label>
        <input id="s" v-model="form.subdir" class="mono" placeholder="detection-rules" />
      </div>
      <div>
        <label for="e">Pull</label>
        <select id="e" v-model.number="form.every_seconds">
          <option v-for="[secs, label] in EVERY" :key="secs" :value="secs">{{ label }}</option>
        </select>
      </div>
      <div>
        <label for="t">Access token (private repositories)</label>
        <input id="t" v-model="form.secret" type="password" autocomplete="new-password" placeholder="leave blank to keep" />
      </div>
    </div>

    <label class="inline"><input v-model="form.enabled" type="checkbox" /> pull this feed and load its rules</label>

    <p class="dim tiny">
      Only <code>https</code> and <code>ssh</code> are accepted. A feed supplies rules and nothing
      else — no rule it brings can act on a mailbox until you attach an action to it.
    </p>

    <div class="row">
      <button class="primary" type="submit" :disabled="save.isPending.value">Save feed</button>
      <button type="button" @click="editing = false">Cancel</button>
    </div>
  </form>

  <QueryState
    :loading="query.isLoading.value"
    :error="query.error.value"
    :empty="feeds.length === 0"
    :has-data="!!query.data.value"
    empty-text="No feed is configured, so the engine has only whatever local rules are mounted."
  >
    <table>
      <thead>
        <tr><th>Feed</th><th class="right">Rules</th><th>Last pull</th><th>State</th><th></th></tr>
      </thead>
      <tbody>
        <tr v-for="f in feeds" :key="f.id">
          <td>
            <strong>{{ f.name }}</strong>
            <div class="mono tiny dim break">{{ f.url }}<template v-if="f.subdir"> · {{ f.subdir }}</template></div>
          </td>
          <td class="right mono">{{ count(f.rule_count) }}</td>
          <td class="dim nowrap">
            <span :title="stamp(f.last_sync)">{{ ago(f.last_sync) || 'never' }}</span>
            <div v-if="f.last_commit" class="mono tiny faint">{{ f.last_commit.slice(0, 8) }}</div>
          </td>
          <td>
            <span class="tag" :class="f.enabled ? 'ok' : 'mute'">{{ f.enabled ? 'pulling' : 'paused' }}</span>
            <span v-if="f.has_secret" class="tag act">token</span>
            <div v-if="f.last_error" class="tiny bad-t">{{ f.last_error }}</div>
          </td>
          <td class="right nowrap">
            <button class="link" type="button" :disabled="syncing === f.id" @click="syncNow(f)">
              {{ syncing === f.id ? 'syncing…' : 'sync now' }}
            </button>
            <button class="link" type="button" @click="open(f)">edit</button>
            <button class="link danger-link" type="button" @click="removeFeed(f)">remove</button>
          </td>
        </tr>
      </tbody>
    </table>
  </QueryState>
</template>

<style scoped>
.edit { margin-bottom: 1.25rem; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); gap: .75rem; }
.grid input, .grid select { width: 100%; }
.inline { display: flex; align-items: center; gap: .4rem; margin: 0; }
.tiny { font-size: .78rem; }
.break { overflow-wrap: anywhere; }
.bad-t { color: var(--bad); }
.danger-link { color: var(--bad); }
td .tag { margin-right: .25rem; }
td button.link + button.link { margin-left: .75rem; }
code { font-family: var(--mono); font-size: .9em; }
</style>
