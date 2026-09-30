<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed, ref } from 'vue'
import { useMutation, useQueryClient } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { MessagePage } from '@/api/types.gen'
import { useSession, can } from '@/composables/session'
import { toast } from '@/composables/toast'
import { ago, arr, iso, stamp, count } from '@/format'
import VerdictTag from '@/components/VerdictTag.vue'
import InsightList from '@/components/InsightList.vue'
import DomainPanel from '@/components/DomainPanel.vue'

// Takes an already-loaded page rather than fetching one, so the same markup serves
// both a stored message and the analyzer's result for a message that was
// deliberately never stored.
const props = defineProps<{ page: MessagePage }>()
const qc = useQueryClient()
const { data: session } = useSession()

const page = computed(() => props.page)
const d = computed(() => props.page.detail)
const id = computed(() => props.page.id)

type Tab = 'summary' | 'rendered' | 'links' | 'files' | 'auth' | 'headers' | 'mdm'
const tab = ref<Tab>('summary')

const TABS = computed<[Tab, string, number][]>(() => [
  ['summary', 'Summary', 0],
  ['rendered', 'Rendered', 0],
  ['links', 'Links', arr(d.value?.links).length],
  ['files', 'Attachments', arr(d.value?.attachments).length],
  ['auth', 'Authentication', 0],
  ['headers', 'Headers', 0],
  ['mdm', 'Data model', 0],
])

const isAnalyst = computed(() => can(session.value?.user.role, 'analyst'))
const readOnly = computed(() => session.value?.read_only === true)

function invalidate() {
  qc.invalidateQueries({ queryKey: ['message', id.value] })
  qc.invalidateQueries({ queryKey: ['triage'] })
  qc.invalidateQueries({ queryKey: ['session'] })
}

const act = useMutation({
  mutationFn: (vars: { action: string; force?: boolean }) =>
    api.post(`/messages/${encodeURIComponent(id.value)}/act`, {
      action: vars.action,
      reason: '',
      disposition: '',
      force: vars.force ?? false,
    }),
  onSuccess: (_r, vars) => {
    toast.ok(`${vars.action} applied`)
    invalidate()
  },
  onError: (e) => toast.err(e),
})

const setTriage = useMutation({
  mutationFn: (state: string) =>
    api.post(`/messages/${encodeURIComponent(id.value)}/triage`, { state, note: '' }),
  onSuccess: (_r, state) => {
    toast.ok(`Marked ${state.replace('_', ' ')}`)
    invalidate()
  },
  onError: (e) => toast.err(e),
})

function quarantine() {
  // Custody is what makes this reversible, so the confirmation states which of the
  // two very different things is about to happen instead of asking "are you sure".
  const held = d.value?.held
  const msg = held
    ? 'Remove this message from the mailbox and hold the only copy here? It can be released again.'
    : 'This message is NOT held by the engine: removing it from the mailbox destroys the only copy, and it cannot be released. Continue?'
  if (!confirm(msg)) return
  act.mutate({ action: 'quarantine', force: !held })
}

const raw = computed(() => `/messages/${encodeURIComponent(id.value)}/raw`)
</script>

<template>
  <!-- detail is a pointer on the wire, so narrow once here rather than
       guarding every field below. -->
  <template v-if="d">
    <header class="head">
      <div class="grow">
        <h1>{{ d.summary.subject || '(no subject)' }}</h1>
        <div class="row sub">
          <VerdictTag :verdict="page.verdict" />
          <span v-if="d.transient" class="tag mute" title="Analysed without being recorded">not stored</span>
          <span v-if="d.held" class="tag act" title="The engine holds the original bytes">held</span>
          <span class="mono dim">{{ d.summary.sender }}</span>
          <span v-if="d.summary.date" class="dim" :title="iso(d.summary.date)">{{ ago(d.summary.date) }}</span>
        </div>
        <p v-if="d.analysed_at" class="faint tiny">
          <template v-if="d.recomputed">Re-evaluated just now against the current rule set.</template>
          <template v-else>Stored analysis from {{ stamp(d.analysed_at) }}.</template>
        </p>
      </div>

      <div v-if="isAnalyst && !d.transient" class="row">
        <button v-if="!readOnly" class="danger" :disabled="act.isPending.value" @click="quarantine">Quarantine</button>
        <button v-if="!readOnly && d.held" :disabled="act.isPending.value" @click="act.mutate({ action: 'release' })">
          Release
        </button>
        <a class="dl" :href="raw" download>Download .eml</a>
      </div>
    </header>

    <!-- The judgement, kept visually separate from the mailbox action. -->
    <div v-if="isAnalyst && !d.transient && !readOnly" class="panel states">
      <span class="dim">Triage</span>
      <button
        v-for="s in arr(page.states).filter((q) => q.key !== 'all')"
        :key="s.key"
        type="button"
        :class="{ on: d.triage.state === s.key }"
        :title="s.hint"
        :disabled="setTriage.isPending.value"
        @click="setTriage.mutate(s.key)"
      >
        {{ s.label }}
      </button>
    </div>

    <div v-if="arr(d.missing).length" class="warn missing">
      <strong>Some rules could not be answered.</strong>
      These capabilities were unavailable: {{ arr(d.missing).join(', ') }}. Anything depending on
      them is reported as indeterminate rather than clean.
    </div>

    <nav class="tabs">
      <button v-for="[key, label, n] in TABS" :key="key" type="button" :class="{ on: tab === key }" @click="tab = key">
        {{ label }}<span v-if="n" class="n">{{ n }}</span>
      </button>
    </nav>

    <!-- Summary -->
    <section v-if="tab === 'summary'" class="cols">
      <div>
        <h2 v-if="arr(d.detections).length" class="bad-h">Matched</h2>
        <ul v-if="arr(d.detections).length" class="rules">
          <li v-for="r in arr(d.detections)" :key="r.id">
            <RouterLink :to="`/detections/${encodeURIComponent(r.id)}`" :class="`sev-${r.severity}`">{{ r.name }}</RouterLink>
            <span class="tag" :class="`sev-${r.severity}`">{{ r.severity }}</span>
            <p v-if="r.description" class="dim tiny">{{ r.description }}</p>
          </li>
        </ul>

        <p v-if="!arr(d.detections).length && !arr(d.indeterminate).length" class="dim">
          No rule matched this message.
        </p>

        <template v-if="d.learned">
          <h2>Learned score</h2>
          <p>
            {{ d.learned.score.toFixed(2) }}
            <span class="dim">({{ d.learned.agreement }})</span>
            {{ ' ' }}
            <span v-if="d.learned.advisory" class="tag mute">advisory</span>
          </p>
        </template>
      </div>

      <div>
        <InsightList title="Identity" :items="arr(page.identity)" />
        <InsightList title="Reputation" :items="arr(page.reputation)" />
        <InsightList title="Content" :items="arr(page.content)" />

        <template v-if="d.sender">
          <h3>Sender domain</h3>
          <DomainPanel :info="d.sender" :domain="d.sender.root_domain || d.sender.domain" />
        </template>

        <template v-if="d.origin">
          <h3>Sending server</h3>
          <dl class="summary">
            <dt>Address</dt>
            <dd class="mono">{{ d.origin.ip }}</dd>
            <template v-if="d.origin.rdns"><dt>Reverse name</dt><dd class="mono">{{ d.origin.rdns }}</dd></template>
            <template v-if="d.origin.asn"><dt>Network</dt><dd>AS{{ d.origin.asn }} {{ d.origin.asn_organization }}</dd></template>
            <template v-if="d.origin.country"><dt>Country</dt><dd>{{ d.origin.country }}</dd></template>
            <template v-if="d.origin.abuse_email"><dt>Abuse contact</dt><dd class="mono">{{ d.origin.abuse_email }}</dd></template>
          </dl>
        </template>

        <details v-if="arr(d.indeterminate).length" class="indet">
          <summary>
            Indeterminate
            <span class="n">{{ arr(d.indeterminate).length }}</span>
            <span class="faint">— rules that could not be answered</span>
          </summary>
          <ul class="rules">
            <li v-for="r in arr(d.indeterminate)" :key="r.id">
              <RouterLink :to="`/detections/${encodeURIComponent(r.id)}`">{{ r.name }}</RouterLink>
              <span v-if="arr(r.missing).length" class="faint tiny">needs {{ arr(r.missing).join(', ') }}</span>
            </li>
          </ul>
        </details>
      </div>
    </section>

    <!-- Rendered -->
    <section v-else-if="tab === 'rendered'">
      <p class="dim tiny">
        A picture taken by a browser with no network access, so nothing in the message can phone
        home by being looked at.
      </p>
      <img v-if="page.screenshot" class="shot" :src="page.screenshot" alt="Rendered message" />
      <div v-else class="empty">No rendering is available for this message.</div>
    </section>

    <!-- Links -->
    <section v-else-if="tab === 'links'">
      <div v-if="!arr(d.links).length" class="empty">No links in this message.</div>
      <table v-else>
        <thead><tr><th>Destination</th><th>Shown as</th><th>Domain</th><th>Notes</th></tr></thead>
        <tbody>
          <tr v-for="(l, n) in arr(d.links)" :key="n">
            <td class="mono break">{{ l.url }}</td>
            <td>{{ l.display_text }}</td>
            <td class="mono">
              {{ l.root_domain || l.domain }}
              <div v-if="l.domain_age_days !== undefined" class="tiny" :class="l.domain_age_days < 30 ? 'warn-t' : 'faint'">
                registered {{ count(l.domain_age_days) }} days ago
              </div>
              <div v-else-if="l.domain_known && !l.domain_registered" class="tiny warn-t">not registered</div>
              <div v-else-if="!l.domain_known" class="tiny faint">registration unknown</div>
            </td>
            <td>
              <span v-if="l.text_mismatch" class="tag bad">shows another address</span>
              <span v-if="l.shortener" class="tag unknown">shortener</span>
            </td>
          </tr>
        </tbody>
      </table>
    </section>

    <!-- Attachments -->
    <section v-else-if="tab === 'files'">
      <div v-if="!arr(d.attachments).length" class="empty">No attachments.</div>
      <table v-else>
        <thead><tr><th>Name</th><th>Type</th><th class="right">Size</th><th>SHA-256</th></tr></thead>
        <tbody>
          <tr v-for="(f, n) in arr(d.attachments)" :key="n">
            <td>{{ f.file_name }}</td>
            <td class="mono">{{ f.content_type }}</td>
            <td class="right nowrap">{{ count(f.size) }} B</td>
            <td class="mono break tiny">{{ f.sha256 }}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <!-- Authentication -->
    <section v-else-if="tab === 'auth'">
      <div class="row badges">
        <span
          v-for="b in arr(d.auth_badges)"
          :key="b.name"
          class="tag"
          :class="b.state === 'pass' ? 'ok' : b.state === 'fail' ? 'bad' : 'unknown'"
          :title="b.detail"
        >
          {{ b.name }} {{ b.state }}
        </span>
      </div>
      <pre class="mono json">{{ JSON.stringify(d.authentication, null, 2) }}</pre>
    </section>

    <!-- Headers -->
    <section v-else-if="tab === 'headers'">
      <pre class="mono json">{{ JSON.stringify(d.headers, null, 2) }}</pre>
    </section>

    <!-- Data model -->
    <section v-else>
      <pre class="mono json">{{ JSON.stringify(page.mdm, null, 2) }}</pre>
    </section>
  </template>
</template>

<style scoped>
.head { display: flex; gap: 1rem; align-items: flex-start; flex-wrap: wrap; margin-bottom: .75rem; }
.sub { margin-top: .25rem; gap: .5rem; }
.tiny { font-size: .8rem; }
.dl { align-self: center; font-size: .88rem; }

.states { display: flex; gap: .4rem; align-items: center; flex-wrap: wrap; padding: .5rem .8rem; margin-bottom: .75rem; }
.states button { font-size: .85rem; padding: .25rem .5rem; }
.states button.on { border-color: var(--accent); color: var(--accent); }

.missing { margin-bottom: 1rem; }

.tabs { display: flex; gap: .25rem; border-bottom: 1px solid var(--line); margin: 1rem 0 1.25rem; flex-wrap: wrap; }
.tabs button {
  background: none; border: none; border-bottom: 2px solid transparent;
  border-radius: 0; color: var(--dim); padding: .45rem .7rem;
}
.tabs button:hover { background: var(--panel); color: var(--fg); }
.tabs button.on { color: var(--fg); border-bottom-color: var(--accent); }
.n { margin-left: .35rem; font-size: .72rem; color: var(--faint); background: var(--panel-2); border-radius: 999px; padding: 0 .35rem; }

/* One column. The summary reads top to bottom — what matched, then what is known
   about the sender — and a sidebar only made that order ambiguous. Capped in width
   because a definition list stretched across a wide monitor puts the label and its
   value too far apart to pair up by eye. */
.cols { max-width: 62rem; }
.cols > div + div { margin-top: .5rem; }

/* The long tail of unanswerable rules, folded shut. In one column, left open it
   pushed who-sent-this off the bottom of the screen; it is reference, not headline. */
.indet { margin-top: 1.75rem; border-top: 1px solid var(--line); padding-top: .75rem; }
.indet summary { cursor: pointer; font-weight: 600; }
.indet summary .n {
  font-weight: 400; font-size: .78rem; color: var(--faint);
  background: var(--panel-2); border-radius: 999px; padding: 0 .4rem;
}
.indet summary .faint { font-weight: 400; font-size: .85rem; }
.indet .rules { margin-top: .75rem; }

.bad-h { color: var(--bad); }
.rules { list-style: none; padding: 0; margin: .25rem 0 0; display: flex; flex-direction: column; gap: .6rem; align-items: flex-start; }
.rules li { display: flex; flex-direction: column; gap: .15rem; align-items: flex-start; }
.rules p { margin: 0; }

.shot { max-width: 100%; border: 1px solid var(--line); border-radius: var(--r); background: #fff; }
.json { background: var(--panel); border: 1px solid var(--line); border-radius: var(--r); padding: .8rem; overflow: auto; max-height: 40rem; font-size: .82rem; }
.break { overflow-wrap: anywhere; }
.warn-t { color: var(--unknown); }
.badges { margin-bottom: .75rem; }
</style>
