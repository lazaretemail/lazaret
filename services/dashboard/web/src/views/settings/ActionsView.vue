<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { ActionType, ConfiguredAction, Rule } from '@/api/types.gen'
import { arr, count } from '@/format'
import { useSave } from '@/composables/mutate'
import PageHead from '@/components/PageHead.vue'
import QueryState from '@/components/QueryState.vue'

const query = useQuery({
  queryKey: ['actions'],
  queryFn: () =>
    api.get<{ types: ActionType[]; actions: ConfiguredAction[]; by_rule: Record<string, ConfiguredAction[]> | null }>(
      '/settings/actions',
    ),
})
const rulesQuery = useQuery({
  queryKey: ['detections'],
  queryFn: () => api.get<{ rules: Rule[] }>('/detections'),
})

const types = computed(() => arr(query.data.value?.types))
const actions = computed(() => arr(query.data.value?.actions))

const editing = ref(false)
const form = reactive<{ id: string; label: string; type: string; enabled: boolean; config: Record<string, string> }>({
  id: '', label: '', type: '', enabled: true, config: {},
})
const chosen = computed(() => types.value.find((t) => t.type === form.type))

function open(a?: ConfiguredAction) {
  editing.value = true
  form.id = a?.id ?? ''
  form.label = a?.label ?? ''
  form.type = a?.type ?? (types.value[0]?.type ?? '')
  form.enabled = a?.enabled ?? true
  form.config = { ...(a?.config ?? {}) }
}

const invalidate = [['actions'], ['detections']]
const save = useSave({
  run: () => api.post('/settings/actions', { ...form, rules: 0, updated_at: '', updated_by: '' }),
  done: 'Action saved.',
  invalidate,
})
const remove = useSave({
  run: (id: string) => api.del(`/settings/actions/${encodeURIComponent(id)}`),
  done: 'Action deleted.',
  invalidate,
})

// ---- attaching to rules -------------------------------------------------

const attachAction = ref('')
const ruleFilter = ref('')
const picked = ref<Set<string>>(new Set())

const matchingRules = computed(() => {
  const needle = ruleFilter.value.trim().toLowerCase()
  if (!needle) return []
  return arr(rulesQuery.data.value?.rules).filter((r) => r.name.toLowerCase().includes(needle)).slice(0, 40)
})

const attach = useSave({
  run: (vars: { remove: boolean }) =>
    api.post('/settings/actions/attach', {
      rule_ids: [...picked.value],
      action_ids: [attachAction.value],
      remove: vars.remove,
    }),
  done: 'Rules updated.',
  invalidate,
})

function toggleRule(id: string) {
  const next = new Set(picked.value)
  next.has(id) ? next.delete(id) : next.add(id)
  picked.value = next
}

function submit() {
  save.mutate()
  editing.value = false
}
</script>

<template>
  <PageHead
    title="Actions"
    hint="What happens when a rule fires. A rule with no action attached only queues the message for review."
  >
    <template #actions>
      <button class="primary" type="button" @click="open()">New action</button>
    </template>
  </PageHead>

  <form v-if="editing" class="panel stack edit" @submit.prevent="submit">
    <div class="grid">
      <div><label for="l">Name</label><input id="l" v-model="form.label" required placeholder="Quarantine confirmed phishing" /></div>
      <div>
        <label for="t">Type</label>
        <select id="t" v-model="form.type">
          <option v-for="t in types" :key="t.type" :value="t.type">{{ t.label }}</option>
        </select>
      </div>
    </div>

    <p v-if="chosen" class="dim tiny">
      {{ chosen.detail }}
      <span v-if="chosen.destructive" class="tag bad">destructive</span>
      <span v-if="chosen.needs_custody" class="tag unknown">needs custody</span>
      <span v-for="p in arr(chosen.providers)" :key="p" class="tag mute">{{ p }}</span>
    </p>

    <div v-if="arr(chosen?.params).length" class="grid">
      <div v-for="p in arr(chosen?.params)" :key="p.name">
        <label :for="`p-${p.name}`">{{ p.label }}<span v-if="p.required"> *</span></label>
        <input :id="`p-${p.name}`" v-model="form.config[p.name]" :placeholder="p.placeholder" :required="p.required" />
        <div v-if="p.detail" class="faint tiny">{{ p.detail }}</div>
      </div>
    </div>

    <label class="inline"><input v-model="form.enabled" type="checkbox" /> enabled</label>
    <div class="row">
      <button class="primary" type="submit" :disabled="save.isPending.value">Save action</button>
      <button type="button" @click="editing = false">Cancel</button>
    </div>
  </form>

  <QueryState
    :loading="query.isLoading.value"
    :error="query.error.value"
    :empty="actions.length === 0"
    empty-text="No action is configured, so every detection is queued for review."
  >
    <table>
      <thead><tr><th>Name</th><th>Type</th><th class="right">Rules</th><th>State</th><th></th></tr></thead>
      <tbody>
        <tr v-for="a in actions" :key="a.id">
          <td>{{ a.label }}</td>
          <td class="dim">{{ a.type }}</td>
          <td class="right mono">{{ count(a.rules) }}</td>
          <td><span class="tag" :class="a.enabled ? 'ok' : 'mute'">{{ a.enabled ? 'enabled' : 'disabled' }}</span></td>
          <td class="right nowrap">
            <button class="link" type="button" @click="open(a)">edit</button>
            <button class="link danger-link" type="button" @click="remove.mutate(a.id)">delete</button>
          </td>
        </tr>
      </tbody>
    </table>
  </QueryState>

  <h2>Attach an action to rules</h2>
  <div class="panel stack">
    <div class="row">
      <select v-model="attachAction" aria-label="Action">
        <option value="" disabled>choose an action…</option>
        <option v-for="a in actions" :key="a.id" :value="a.id">{{ a.label }}</option>
      </select>
      <input v-model="ruleFilter" type="search" placeholder="Find rules…" aria-label="Find rules" style="min-width: 18rem" />
      <span v-if="picked.size" class="dim">{{ count(picked.size) }} selected</span>
      <button class="primary" type="button" :disabled="!attachAction || !picked.size" @click="attach.mutate({ remove: false })">
        Attach
      </button>
      <button type="button" :disabled="!attachAction || !picked.size" @click="attach.mutate({ remove: true })">
        Detach
      </button>
    </div>

    <p v-if="!ruleFilter.trim()" class="dim">Search for the rules you want to change.</p>
    <ul v-else class="picklist">
      <li v-for="r in matchingRules" :key="r.id">
        <label class="inline">
          <input type="checkbox" :checked="picked.has(r.id)" @change="toggleRule(r.id)" />
          {{ r.name }}
        </label>
      </li>
    </ul>
  </div>
</template>

<style scoped>
.edit { margin-bottom: 1.25rem; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); gap: .75rem; }
.grid input, .grid select { width: 100%; }
.inline { display: flex; align-items: center; gap: .4rem; margin: 0; }
.tiny { font-size: .8rem; }
.danger-link { color: var(--bad); margin-left: .75rem; }
.picklist { list-style: none; padding: 0; margin: 0; max-height: 22rem; overflow: auto; }
.picklist li { padding: .15rem 0; }
</style>
