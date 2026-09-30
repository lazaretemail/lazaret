// SPDX-License-Identifier: AGPL-3.0-only

import { StreamLanguage, HighlightStyle, syntaxHighlighting } from '@codemirror/language'
import { tags as t } from '@lezer/highlight'

/**
 * MQL highlighting.
 *
 * A stream tokenizer rather than a Lezer grammar. Highlighting needs to know what a
 * token *is*, not how the expression nests, and a hand-written grammar would be a
 * second parser to keep in step with the real one in Go — the checker already tells
 * us when something is actually wrong, so this only has to be right about colours.
 *
 * The one rule worth care: inside a single-quoted string there are no escapes at
 * all. `strings.count(subject.subject, '\')` is a real corpus rule — a string whose
 * only content is a backslash, immediately before the closing quote. A tokenizer
 * that treats \' as an escape swallows the terminator and miscolours the rest of
 * the file.
 */

const KEYWORDS = new Set([
  'and', 'or', 'not', 'in', 'is', 'null', 'any', 'all', 'none', 'of',
  'true', 'false', 'filter', 'map', 'distinct', 'flatten', 'sum', 'ratio',
  'length', 'coalesce', 'keys', 'values',
])

export const mqlLanguage = StreamLanguage.define({
  name: 'mql',

  token(stream) {
    if (stream.eatSpace()) return null

    // Comments.
    if (stream.match('//')) {
      stream.skipToEnd()
      return 'comment'
    }

    // Raw strings: no escapes, '' is the only special sequence.
    if (stream.peek() === "'") {
      stream.next()
      for (;;) {
        const ch = stream.next()
        if (ch === undefined) break
        if (ch === "'") {
          if (stream.peek() === "'") {
            stream.next() // an escaped quote, keep going
            continue
          }
          break
        }
      }
      return 'string'
    }

    // Double-quoted strings do take escapes.
    if (stream.peek() === '"') {
      stream.next()
      let escaped = false
      for (;;) {
        const ch = stream.next()
        if (ch === undefined) break
        if (escaped) {
          escaped = false
          continue
        }
        if (ch === '\\') escaped = true
        else if (ch === '"') break
      }
      return 'string'
    }

    // $named lists.
    if (stream.match(/^\$[A-Za-z_][A-Za-z0-9_]*/)) return 'list'

    // Numbers.
    if (stream.match(/^\d+(\.\d+)?/)) return 'number'

    // A dotted identifier, possibly a function call or a scope climb (.. / ...).
    if (stream.match(/^\.{1,3}/)) return 'operator'

    if (stream.match(/^[A-Za-z_][A-Za-z0-9_]*/)) {
      const word = stream.current()
      if (KEYWORDS.has(word)) return 'keyword'
      // A name immediately followed by ( or . that continues into a call.
      if (stream.peek() === '(') return 'function'
      return 'variable'
    }

    if (stream.match(/^(==|!=|<=|>=|=~|~|<|>|=)/)) return 'operator'

    stream.next()
    return null
  },

  languageData: {
    commentTokens: { line: '//' },
    closeBrackets: { brackets: ['(', '[', '"', "'"] },
  },
})

/** Colours drawn from the console's own tokens, so the editor is part of the page. */
export const mqlHighlight = syntaxHighlighting(
  HighlightStyle.define([
    { tag: t.comment, color: 'var(--faint)', fontStyle: 'italic' },
    { tag: t.string, color: 'var(--ok)' },
    { tag: t.number, color: 'var(--ok)' },
    { tag: t.keyword, color: 'var(--amber)', fontWeight: '500' },
    { tag: t.operator, color: 'var(--dim)' },
    { tag: t.function(t.variableName), color: 'var(--link)' },
    { tag: t.variableName, color: 'var(--fg)' },
    { tag: t.atom, color: 'var(--amber)' },
  ]),
)

// StreamLanguage token names map onto highlight tags by this table.
export const mqlTokenTable = {
  list: t.atom,
  function: t.function(t.variableName),
}
