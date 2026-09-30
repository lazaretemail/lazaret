// SPDX-License-Identifier: AGPL-3.0-only

import type { Completion, CompletionContext, CompletionResult } from '@codemirror/autocomplete'
import { mqlSchema, resolvePath, type MqlSchema, type MqlType } from './schema'

/**
 * Completion for MQL.
 *
 * Four things an author is ever typing: a field path, a function, a $list, or a
 * keyword. Each is offered from the engine's own schema, so the suggestions are
 * what this deployment will actually accept.
 */

let schema: MqlSchema | null = null

/** Load the schema in the background; completion is inert until it arrives. */
export async function primeSchema(): Promise<void> {
  try {
    schema = await mqlSchema()
  } catch {
    // Completion is a convenience. An editor that still types is better than an
    // error banner because a schema fetch failed.
  }
}

function fieldCompletions(type: MqlType, fromArray = false): Completion[] {
  if (!type.fields) return []
  return Object.entries(type.fields).map(([name, f]) => {
    const c: Completion = {
      label: name,
      type: f.type ? 'property' : kindIcon(f.kind),
      detail: f.kind === 'array' ? `${f.kind} of ${f.type ?? 'value'}` : f.kind,
      boost: fromArray ? 1 : 0,
    }
    const info = f.doc || (f.enum?.length ? `one of: ${f.enum.join(', ')}` : '')
    if (info) c.info = info
    return c
  })
}

function kindIcon(kind: string): string {
  switch (kind) {
    case 'string':
    case 'bytes':
      return 'text'
    case 'integer':
    case 'float':
      return 'number'
    case 'boolean':
      return 'keyword'
    case 'array':
    case 'map':
      return 'property'
    default:
      return 'variable'
  }
}

function functionCompletions(s: MqlSchema): Completion[] {
  return s.functions.map((f) => {
    const params = (f.params ?? []).join(', ')
    const kw = (f.keywords ?? []).map((k) => `, ${k}`).join('')
    const c: Completion = {
      label: f.name,
      type: 'function',
      detail: `(${params}${f.variadic ? ', …' : ''}${kw})${f.returns ? ` → ${f.returns}` : ''}`,
      apply: `${f.name}(`,
      boost: f.capability ? -1 : 0,
    }
    // Naming the capability matters: a function that needs enrichment costs a
    // network call per message and turns the rule indeterminate when the service is
    // down. That is worth knowing before you type it, not after.
    const info = [f.doc, f.capability ? `needs ${f.capability}` : ''].filter(Boolean).join('\n\n')
    if (info) c.info = info
    return c
  })
}

/**
 * The collection an `any(...)`/`all(...)`/`filter(...)` is iterating, so a bare `.`
 * inside one completes the element's fields.
 *
 * `any(` is the single most used function in the corpus — 4427 times — and inside
 * it every field reference starts with a dot. Completion that gives up there would
 * miss most of what anyone writes.
 */
function enclosingCollection(text: string): string[] | null {
  let depth = 0
  for (let i = text.length - 1; i >= 0; i--) {
    const ch = text[i]
    if (ch === ')') depth++
    else if (ch === '(') {
      if (depth === 0) {
        const before = text.slice(0, i)
        const m = /\b(any|all|none|filter|map|distinct|sum|ratio|length)\s*$/.exec(before)
        if (!m) return null
        // The first argument, up to the comma that ends it.
        const inner = text.slice(i + 1)
        const arg = inner.split(',')[0]?.trim() ?? ''
        const path = /^[A-Za-z_][A-Za-z0-9_.]*$/.test(arg) ? arg.split('.') : null
        return path
      }
      depth--
    }
  }
  return null
}

export function mqlCompletions(context: CompletionContext): CompletionResult | null {
  if (!schema) return null
  const s = schema

  // $list names.
  const list = context.matchBefore(/\$[A-Za-z0-9_]*/)
  if (list) {
    return {
      from: list.from + 1,
      options: s.lists.map((name) => ({ label: name, type: 'constant', detail: 'list' })),
      validFor: /^[A-Za-z0-9_]*$/,
    }
  }

  const before = context.state.sliceDoc(0, context.pos)

  // A dotted path: complete the fields of whatever it resolves to.
  const path = context.matchBefore(/[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z0-9_]*)+/)
  if (path) {
    const segments = path.text.split('.')
    const partial = segments.pop() ?? ''
    const target = resolvePath(s, segments)
    if (target) {
      return {
        from: context.pos - partial.length,
        options: fieldCompletions(target),
        validFor: /^[A-Za-z0-9_]*$/,
      }
    }
    return null
  }

  // A bare leading dot: the loop variable inside any(...)/filter(...).
  const dot = context.matchBefore(/\.[A-Za-z0-9_]*/)
  if (dot && !/[A-Za-z0-9_)\]]\s*$/.test(before.slice(0, dot.from))) {
    const collection = enclosingCollection(before.slice(0, dot.from))
    if (collection) {
      const target = resolvePath(s, collection)
      if (target) {
        return {
          from: dot.from + 1,
          options: fieldCompletions(target, true),
          validFor: /^[A-Za-z0-9_]*$/,
        }
      }
    }
    return null
  }

  // A bare word: root fields, functions and keywords together, which is what the
  // start of nearly every line wants.
  const word = context.matchBefore(/[A-Za-z_][A-Za-z0-9_.]*/)
  if (!word && !context.explicit) return null
  const root = s.types[s.root]
  return {
    from: word ? word.from : context.pos,
    options: [
      ...(root ? fieldCompletions(root) : []),
      ...functionCompletions(s),
      ...s.keywords.map((k) => ({ label: k, type: 'keyword' as const })),
    ],
    validFor: /^[A-Za-z0-9_.]*$/,
  }
}
