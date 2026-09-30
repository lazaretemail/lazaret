<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { api, ApiError } from '@/api/http'
import type { GraphApp, GraphDirectory, GraphDirectoryUser, BulkAdded } from '@/api/types.gen'
import { arr, count, stamp } from '@/format'
import { useSave } from '@/composables/mutate'
import { toast } from '@/composables/toast'
import PageHead from '@/components/PageHead.vue'
import QueryState from '@/components/QueryState.vue'

const query = useQuery({ queryKey: ['graphapp'], queryFn: () => api.get<GraphApp>('/settings/microsoft') })
const app = computed(() => query.data.value)

const form = reactive({ directory_id: '', client_id: '', secret: '', cloud: '' })
watch(app, (a) => {
  if (!a) return
  form.directory_id = a.directory_id
  form.client_id = a.client_id
  form.cloud = a.cloud ?? ''
}, { immediate: true })

// Nearly every tenant is on the public cloud, so it leads and the rest are named the
// way Microsoft's own documentation names them — an administrator who needs one of
// these knows which, and an administrator who does not should not have to think.
const CLOUDS: [string, string][] = [
  ['', 'Public (commercial)'],
  ['usgov', 'US Government (GCC High)'],
  ['usgovdod', 'US Government (DoD)'],
  ['china', 'China (21Vianet)'],
]

const invalidate = [['graphapp'], ['mailboxes']]
const save = useSave({
  run: () => api.put('/settings/microsoft', { ...form, notify_url: '', has_secret: false, updated_by: '' }),
  done: 'Microsoft 365 application saved.',
  invalidate,
})
const remove = useSave({
  run: () => api.del('/settings/microsoft'),
  done: 'Application removed.',
  invalidate,
})

function forget() {
  if (confirm('Remove the registered application? Graph collection stops until one is configured again.')) {
    remove.mutate()
  }
}

// ---- walking the directory ----------------------------------------------
//
// Fetched on demand rather than with the page. It is a call against somebody's
// Microsoft tenant returning every account in the organisation, which is not a thing to
// do because an administrator opened a settings page.

const dir = ref<GraphDirectory | null>(null)
const dirError = ref<unknown>(null)
const scanning = ref(false)
const chosen = ref<Set<string>>(new Set())
const startEnabled = ref(true)

/** Accounts not already collected — the ones a selection can act on. */
const selectable = computed(() =>
  arr(dir.value?.users).filter((u: GraphDirectoryUser) => !u.configured),
)
const allChosen = computed(
  () => selectable.value.length > 0 && chosen.value.size === selectable.value.length,
)

async function scan() {
  scanning.value = true
  dirError.value = null
  try {
    dir.value = await api.get<GraphDirectory>('/settings/directory')
    // Nothing pre-selected. Four hundred mailboxes is a large thing to configure and
    // the administrator should have to say so, not merely fail to untick.
    chosen.value = new Set()
  } catch (e) {
    dir.value = null
    dirError.value = e
  } finally {
    scanning.value = false
  }
}

function toggle(address: string) {
  const next = new Set(chosen.value)
  if (next.has(address)) next.delete(address)
  else next.add(address)
  chosen.value = next
}

function toggleAll() {
  chosen.value = allChosen.value
    ? new Set()
    : new Set(selectable.value.map((u) => u.mail))
}

const adding = ref(false)
async function addChosen() {
  const addresses = [...chosen.value]
  if (addresses.length === 0) return
  adding.value = true
  try {
    const out = await api.post<BulkAdded>('/settings/mailboxes/bulk', {
      addresses,
      enabled: startEnabled.value,
    })
    toast.ok(
      `${count(out.added)} mailbox${out.added === 1 ? '' : 'es'} added` +
        (startEnabled.value ? ' and collecting.' : ', paused. Resume them under Mailboxes.'),
    )
    chosen.value = new Set()
    // Re-walk so the newly added show as configured rather than as still available.
    await scan()
  } catch (e) {
    toast.err(e)
  } finally {
    adding.value = false
  }
}

function errorText(e: unknown): string {
  if (e instanceof ApiError) return e.message
  return e instanceof Error ? e.message : String(e)
}
</script>

<template>
  <PageHead title="Microsoft 365" hint="The application registration this deployment uses to read and act on mail." />

  <QueryState :loading="query.isLoading.value" :error="query.error.value">
    <form class="stack panel" @submit.prevent="save.mutate()">
      <div class="grid">
        <div>
          <label for="t">Directory (tenant) ID</label>
          <input id="t" v-model="form.directory_id" class="mono" required />
        </div>
        <div>
          <label for="c">Application (client) ID</label>
          <input id="c" v-model="form.client_id" class="mono" required />
        </div>
        <div>
          <label for="cl">Microsoft cloud</label>
          <select id="cl" v-model="form.cloud">
            <option v-for="[value, label] in CLOUDS" :key="value" :value="value">{{ label }}</option>
          </select>
        </div>
        <div>
          <label for="s">Client secret</label>
          <input
            id="s"
            v-model="form.secret"
            type="password"
            autocomplete="new-password"
            :placeholder="app?.has_secret ? 'stored — leave blank to keep' : ''"
          />
        </div>
      </div>

      <p v-if="app?.updated_at" class="dim tiny">
        Last changed {{ stamp(app.updated_at) }}<template v-if="app.updated_by"> by {{ app.updated_by }}</template>.
      </p>

      <div class="row">
        <button class="primary" type="submit" :disabled="save.isPending.value">Save</button>
        <button v-if="app?.client_id" class="danger" type="button" @click="forget">Remove</button>
      </div>
    </form>

    <!--
      Onboarding the estate. Deliberately a button rather than something the page does
      on load: it is a call against the customer's Microsoft tenant that returns every
      account in the organisation.
    -->
    <h2>Mailboxes in this tenant</h2>
    <div class="panel stack">
      <div class="row">
        <button
          class="primary"
          type="button"
          :disabled="scanning || !app?.has_secret"
          @click="scan"
        >
          {{ scanning ? 'Reading the directory…' : dir ? 'Read it again' : 'Read the directory' }}
        </button>
        <span v-if="!app?.has_secret" class="dim tiny">
          Save a registration with a client secret first — there is nothing to authenticate with.
        </span>
      </div>

      <div v-if="dirError" class="err">{{ errorText(dirError) }}</div>

      <template v-if="dir">
        <!--
          Three numbers, because any one of them alone misleads. "431 mailboxes" reads
          as a problem if you have 460 people and do not know 29 are guests.
        -->
        <p class="dim tiny">
          {{ count(dir.accounts_in_directory) }} enabled accounts in the directory,
          {{ count(dir.with_mailboxes) }} with a mailbox,
          {{ count(dir.already_configured) }} already collected here.
          Guests, disabled accounts and accounts with no mailbox are left out.
        </p>

        <div v-if="selectable.length === 0" class="dim">
          Every mailbox in this tenant is already configured.
        </div>

        <template v-else>
          <div class="row wrap">
            <button class="link" type="button" @click="toggleAll">
              {{ allChosen ? 'Select none' : `Select all ${selectable.length}` }}
            </button>
            <label class="inline">
              <input v-model="startEnabled" type="checkbox" />
              start collecting immediately
            </label>
            <button
              class="primary"
              type="button"
              :disabled="chosen.size === 0 || adding"
              @click="addChosen"
            >
              {{ adding ? 'Adding…' : `Add ${chosen.size} mailbox${chosen.size === 1 ? '' : 'es'}` }}
            </button>
          </div>
          <!--
            Said here rather than discovered later. Pointing a new deployment at four
            hundred mailboxes at once is a reasonable thing to want to stage, and
            "paused" is the difference between reviewing the estate and drinking it.
          -->
          <p v-if="!startEnabled" class="dim tiny">
            They will be added paused. Nothing is collected until each is resumed under Mailboxes.
          </p>

          <table class="dirlist">
            <thead>
              <tr>
                <th class="pick"></th>
                <th>Name</th>
                <th>Address</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="u in arr(dir.users)" :key="u.id" :class="{ have: u.configured }">
                <td class="pick">
                  <input
                    type="checkbox"
                    :checked="chosen.has(u.mail)"
                    :disabled="u.configured"
                    :aria-label="`Collect mail for ${u.mail}`"
                    @change="toggle(u.mail)"
                  />
                </td>
                <td>{{ u.display_name || u.user_principal_name }}</td>
                <td class="mono">{{ u.mail }}</td>
                <td>
                  <span v-if="u.configured" class="tag ok">collected</span>
                </td>
              </tr>
            </tbody>
          </table>
        </template>
      </template>
    </div>

    <!--
      Derived, not entered. The callback address is a property of where this
      deployment is reachable, which the operator already told us through
      LAZARET_PUBLIC_URL; asking an admin to retype it only creates a second source
      of truth that can disagree with the first.
    -->
    <h2>How mail is collected</h2>
    <div class="panel">
      <dl class="summary">
        <dt>Notification callback</dt>
        <dd>
          <span v-if="app?.notify_url" class="mono">{{ app.notify_url }}</span>
          <span v-else class="warn-t">
            Not derivable — this deployment has no public URL set. Start the engine with
            <code>LAZARET_PUBLIC_URL</code> (or <code>-public-url</code>) so Microsoft has somewhere
            to send notifications.
          </span>
        </dd>
      </dl>
      <p class="dim tiny">
        Microsoft posts here when a mailbox changes. It is worked out from the deployment's public
        address, so there is nothing to type and nothing to keep in step.
      </p>
    </div>
  </QueryState>
</template>

<style scoped>
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); gap: .75rem; }
.grid input { width: 100%; }
.tiny { font-size: .82rem; }
.row.wrap { flex-wrap: wrap; align-items: center; gap: .75rem; }
.inline { display: flex; align-items: center; gap: .4rem; margin: 0; }
.dirlist { margin-top: .25rem; }
.dirlist .pick { width: 2rem; }
.dirlist tr.have { opacity: .55; }
.warn-t { color: var(--unknown); }
code { font-family: var(--mono); font-size: .9em; }
</style>
