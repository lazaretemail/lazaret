<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { useQuery, useQueryClient } from '@tanstack/vue-query'
import { api } from '@/api/http'
import { toast } from '@/composables/toast'
import type { Mailbox } from '@/api/types.gen'
import { ago, arr } from '@/format'
import { useSave } from '@/composables/mutate'
import PageHead from '@/components/PageHead.vue'
import QueryState from '@/components/QueryState.vue'

const qc = useQueryClient()
const query = useQuery({ queryKey: ['mailboxes'], queryFn: () => api.get<{ mailboxes: Mailbox[] }>('/settings/mailboxes') })
const boxes = computed(() => arr(query.data.value?.mailboxes))

const adding = ref(false)
const form = reactive<Record<string, unknown>>({
  kind: 'imap', address: '', host: '', username: '', secret: '',
  tls_mode: 'starttls', folder: 'INBOX', enabled: true, remediate: false,
})

const invalidate = [['mailboxes'], ['session']]

const save = useSave({
  run: () => api.post('/settings/mailboxes', { ...form }),
  done: 'Mailbox saved. Credentials are held by the engine and never sent back to a browser.',
  invalidate,
})
const remove = useSave({
  run: (id: string) => api.del(`/settings/mailboxes/${encodeURIComponent(id)}`),
  done: 'Mailbox removed.',
  invalidate,
})
const recheck = useSave({
  run: (id: string) => api.post(`/settings/mailboxes/${encodeURIComponent(id)}/recheck`),
  done: 'Credentials re-checked.',
  invalidate,
})

// Pausing rather than removing. Removing destroys the stored credential, so until now
// the only way to stop collecting from a mailbox for an afternoon was to delete it and
// re-enter the password afterwards — which is why people leave it collecting instead.
const setEnabled = useSave({
  run: (v: { id: string; enabled: boolean }) =>
    api.post(`/settings/mailboxes/${encodeURIComponent(v.id)}/enabled`, { enabled: v.enabled }),
  done: 'Mailbox updated.',
  invalidate,
})

const paused = computed(() => boxes.value.filter((b) => !b.enabled).length)

// In bulk, because onboarding an estate produces a list of four hundred and nobody is
// going to click through them one at a time.
//
// Sequential rather than concurrent on purpose: four hundred parallel requests through
// the dashboard to the engine is a self-inflicted thundering herd, and this is a
// settings page, not a hot path.
const busy = ref(false)
async function setAll(enabled: boolean) {
  const targets = boxes.value.filter((b) => b.enabled !== enabled)
  if (targets.length === 0) return
  const verb = enabled ? 'Resume' : 'Pause'
  if (!confirm(`${verb} ${targets.length} mailbox${targets.length === 1 ? '' : 'es'}?`)) return

  busy.value = true
  let done = 0
  try {
    for (const b of targets) {
      await api.post(`/settings/mailboxes/${encodeURIComponent(b.id)}/enabled`, { enabled })
      done++
    }
    toast.ok(`${done} mailbox${done === 1 ? '' : 'es'} ${enabled ? 'resumed' : 'paused'}.`)
  } catch (e) {
    // Says how far it got. Stopping at mailbox 317 of 400 and reporting only the
    // failure would leave an administrator with no idea which state the estate is in.
    toast.err(
      new Error(
        `${done} of ${targets.length} ${enabled ? 'resumed' : 'paused'}, then: ` +
          (e instanceof Error ? e.message : String(e)),
      ),
    )
  } finally {
    busy.value = false
    for (const key of invalidate) qc.invalidateQueries({ queryKey: key })
  }
}

function removeBox(id: string) {
  if (confirm('Remove this mailbox? Collection stops and the stored credential is destroyed.')) {
    remove.mutate(id)
  }
}

function submit() {
  save.mutate()
  adding.value = false
}
</script>

<template>
  <PageHead title="Mailboxes" hint="Where mail is collected from, and whether this deployment may act on it.">
    <template #actions>
      <template v-if="boxes.length > 1">
        <button v-if="paused < boxes.length" class="link" type="button" :disabled="busy" @click="setAll(false)">
          pause all
        </button>
        <button v-if="paused > 0" class="link" type="button" :disabled="busy" @click="setAll(true)">
          resume all
        </button>
      </template>
      <RouterLink class="link" to="/settings/microsoft">Add from Microsoft 365</RouterLink>
      <button class="primary" type="button" @click="adding = !adding">{{ adding ? 'Cancel' : 'Add mailbox' }}</button>
    </template>
  </PageHead>

  <form v-if="adding" class="panel stack add" @submit.prevent="submit">
    <div class="grid">
      <div>
        <label for="k">Kind</label>
        <select id="k" v-model="form.kind">
          <option value="imap">IMAP</option>
          <option value="graph">Microsoft 365</option>
        </select>
      </div>
      <div><label for="a">Address</label><input id="a" v-model="form.address" type="email" required /></div>
      <template v-if="form.kind === 'imap'">
        <div><label for="h">Host</label><input id="h" v-model="form.host" placeholder="imap.example.com" /></div>
        <div><label for="u">Username</label><input id="u" v-model="form.username" autocomplete="off" /></div>
        <div>
          <label for="s">Password or app password</label>
          <input id="s" v-model="form.secret" type="password" autocomplete="new-password" />
        </div>
        <div>
          <label for="t">TLS</label>
          <select id="t" v-model="form.tls_mode">
            <option value="starttls">STARTTLS</option>
            <option value="tls">Implicit TLS</option>
          </select>
        </div>
        <div><label for="f">Folder</label><input id="f" v-model="form.folder" /></div>
      </template>
    </div>

    <label class="inline"><input v-model="form.enabled" type="checkbox" /> collect mail from this mailbox</label>
    <label class="inline">
      <input v-model="form.remediate" type="checkbox" />
      allow this deployment to act on messages here (quarantine, move, trash)
    </label>

    <div class="row"><button class="primary" type="submit" :disabled="save.isPending.value">Save mailbox</button></div>
  </form>

  <QueryState
    :loading="query.isLoading.value"
    :error="query.error.value"
    :empty="boxes.length === 0"
    empty-text="No mailbox is configured, so nothing is being collected."
  >
    <table>
      <thead>
        <tr><th>Address</th><th>Kind</th><th>State</th><th class="right">Messages</th><th>Last seen</th><th></th></tr>
      </thead>
      <tbody>
        <tr v-for="b in boxes" :key="b.id">
          <td class="mono">{{ b.address }}</td>
          <td class="dim">{{ b.kind }}</td>
          <td>
            <span class="tag" :class="b.enabled ? 'ok' : 'mute'">{{ b.enabled ? 'collecting' : 'paused' }}</span>
            <span v-if="b.remediate" class="tag act">may act</span>
            <span v-if="!b.has_secret" class="tag unknown">no credential</span>
            <div v-if="b.last_error" class="tiny bad-t">{{ b.last_error }}</div>
          </td>
          <td class="right mono">{{ b.messages }}</td>
          <td class="dim nowrap">{{ ago(b.last_seen) }}</td>
          <td class="right nowrap">
            <button
              class="link"
              type="button"
              :disabled="setEnabled.isPending.value || busy"
              @click="setEnabled.mutate({ id: b.id, enabled: !b.enabled })"
            >
              {{ b.enabled ? 'pause' : 'resume' }}
            </button>
            <button class="link" type="button" @click="recheck.mutate(b.id)">re-check</button>
            <button class="link danger-link" type="button" @click="removeBox(b.id)">
              remove
            </button>
          </td>
        </tr>
      </tbody>
    </table>
  </QueryState>
</template>

<style scoped>
.add { margin-bottom: 1.25rem; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr)); gap: .75rem; }
.grid input, .grid select { width: 100%; }
.inline { display: flex; align-items: center; gap: .4rem; margin: 0; }
.tiny { font-size: .78rem; }
.bad-t { color: var(--bad); }
td .tag { margin-right: .25rem; }
.danger-link { color: var(--bad); margin-left: .75rem; }
</style>
