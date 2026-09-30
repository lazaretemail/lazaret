<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import { EditorState, type Extension } from '@codemirror/state'
import { EditorView, keymap, lineNumbers, highlightActiveLine, placeholder as cmPlaceholder } from '@codemirror/view'
import { defaultKeymap, history, historyKeymap, indentWithTab } from '@codemirror/commands'
import { autocompletion, closeBrackets, closeBracketsKeymap, completionKeymap } from '@codemirror/autocomplete'
import { bracketMatching, indentOnInput } from '@codemirror/language'
import { linter, lintGutter, lintKeymap } from '@codemirror/lint'

import { mqlLanguage, mqlHighlight } from '@/mql/language'
import { mqlCompletions, primeSchema } from '@/mql/complete'
import { mqlLinter, mqlRequirements } from '@/mql/lint'

const model = defineModel<string>({ default: '' })
const props = withDefaults(
  defineProps<{ kind?: 'rule' | 'query'; placeholder?: string; minHeight?: string }>(),
  { kind: 'query', placeholder: '', minHeight: '9rem' },
)

const host = ref<HTMLDivElement>()
const view = shallowRef<EditorView>()

// What the expression will cost at run time, shown under the editor. An author
// should know a function needs enrichment before they ship the rule, not when the
// verdicts start coming back indeterminate.
const needs = ref<string[]>([])
const lists = ref<string[]>([])

let reqTimer: ReturnType<typeof setTimeout>
function refreshRequirements(source: string) {
  clearTimeout(reqTimer)
  reqTimer = setTimeout(async () => {
    const out = await mqlRequirements(source, props.kind)
    needs.value = out?.needs ?? []
    lists.value = out?.lists ?? []
  }, 500)
}

onMounted(async () => {
  if (!host.value) return
  // Completions come from the engine; prime them before the first keystroke so the
  // very first Ctrl-Space is not the one that fails.
  primeSchema()

  // CodeMirror builds its stylesheet at runtime. The page's CSP allows exactly one
  // nonce, minted per response by the Go handler, rather than opening style-src to
  // every inline style on a console that renders attacker-authored text.
  const nonce = document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')?.content ?? ''

  const extensions: Extension[] = [
    ...(nonce ? [EditorView.cspNonce.of(nonce)] : []),
    lineNumbers(),
    history(),
    bracketMatching(),
    closeBrackets(),
    indentOnInput(),
    highlightActiveLine(),
    lintGutter(),
    mqlLanguage,
    mqlHighlight,
    autocompletion({
      override: [mqlCompletions],
      // Fires on typing rather than only on Ctrl-Space: the point is to discover a
      // field you did not know existed, which requires the list to appear uninvited.
      activateOnTyping: true,
      icons: false,
    }),
    linter(mqlLinter(props.kind), { delay: 400 }),
    keymap.of([...closeBracketsKeymap, ...defaultKeymap, ...historyKeymap, ...completionKeymap, ...lintKeymap, indentWithTab]),
    EditorView.lineWrapping,
    EditorView.updateListener.of((u) => {
      if (u.docChanged) {
        const text = u.state.doc.toString()
        model.value = text
        refreshRequirements(text)
      }
    }),
    EditorView.theme({
      '&': { fontSize: '0.88rem', minHeight: props.minHeight },
      '.cm-scroller': { fontFamily: 'var(--mono)', lineHeight: '1.6' },
      '&.cm-focused': { outline: '2px solid var(--accent)', outlineOffset: '1px' },
    }),
  ]
  if (props.placeholder) extensions.push(cmPlaceholder(props.placeholder))

  view.value = new EditorView({
    parent: host.value,
    state: EditorState.create({ doc: model.value, extensions }),
  })
  if (model.value) refreshRequirements(model.value)
})

// Accept programmatic changes (loading a rule to edit) without fighting the user.
watch(model, (v) => {
  const cm = view.value
  if (!cm || v === cm.state.doc.toString()) return
  cm.dispatch({ changes: { from: 0, to: cm.state.doc.length, insert: v } })
})

onBeforeUnmount(() => {
  clearTimeout(reqTimer)
  view.value?.destroy()
})
</script>

<template>
  <div class="editor">
    <div ref="host" class="cm" />
    <div class="foot">
      <span class="hint">Ctrl-Space for suggestions</span>
      <template v-if="needs.length">
        <span class="dim">needs</span>
        <span v-for="c in needs" :key="c" class="tag unknown" :title="`${c} runs per message and can be unavailable`">{{ c }}</span>
      </template>
      <span v-for="l in lists" :key="l" class="tag mute">${{ l }}</span>
    </div>
  </div>
</template>

<style scoped>
.editor { border: 1px solid var(--line); border-radius: var(--r); overflow: hidden; background: var(--panel); }
.cm :deep(.cm-editor) { background: var(--panel); color: var(--fg); }
.cm :deep(.cm-gutters) { background: var(--panel-2); color: var(--faint); border-right: 1px solid var(--line); }
.cm :deep(.cm-activeLine) { background: color-mix(in srgb, var(--accent) 6%, transparent); }
.cm :deep(.cm-activeLineGutter) { background: transparent; color: var(--dim); }
.cm :deep(.cm-cursor) { border-left-color: var(--fg); }
.cm :deep(.cm-selectionBackground),
.cm :deep(.cm-content ::selection) { background: color-mix(in srgb, var(--accent) 25%, transparent) !important; }
.cm :deep(.cm-tooltip) {
  background: var(--panel-2); border: 1px solid var(--line); border-radius: var(--r);
  color: var(--fg); box-shadow: var(--shadow);
}
.cm :deep(.cm-tooltip-autocomplete ul li[aria-selected]) {
  background: color-mix(in srgb, var(--accent) 22%, transparent); color: var(--fg);
}
.cm :deep(.cm-completionDetail) { color: var(--dim); font-style: normal; margin-left: .75rem; }
.cm :deep(.cm-completionInfo) {
  background: var(--panel-2); border: 1px solid var(--line); color: var(--dim);
  padding: .5rem .6rem; max-width: 26rem; white-space: pre-wrap;
}
.cm :deep(.cm-diagnostic-error) { border-left-color: var(--bad); }
.cm :deep(.cm-lintRange-error) { background: none; text-decoration: underline wavy var(--bad); text-underline-offset: 3px; }

.foot {
  display: flex; flex-wrap: wrap; gap: .35rem; align-items: center;
  padding: .35rem .6rem; border-top: 1px solid var(--line);
  background: var(--panel-2); font-size: .78rem; color: var(--dim);
}
.hint { margin-right: auto; color: var(--faint); }
</style>
