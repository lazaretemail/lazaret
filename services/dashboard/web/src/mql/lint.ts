// SPDX-License-Identifier: AGPL-3.0-only

import type { Diagnostic } from '@codemirror/lint'
import type { EditorView } from '@codemirror/view'
import { api } from '@/api/http'

/**
 * Diagnostics from the engine's own checker.
 *
 * Not a second implementation in the browser. Two checkers will eventually
 * disagree, and the one that matters is the one that decides whether a rule runs —
 * an editor that accepts what the engine rejects is worse than an editor with no
 * checking, because it is confidently wrong.
 */

interface ValidateResponse {
  success?: boolean
  valid?: boolean
  error?: string
  diagnostics?: string
  needs?: string[]
  lists?: string[]
}

/** The engine reports positions as `line:col:` at the head of its message. */
const AT = /^(\d+):(\d+):\s*(.*)$/s

function offsetOf(view: EditorView, line: number, col: number): number {
  const doc = view.state.doc
  if (line < 1 || line > doc.lines) return 0
  const l = doc.line(line)
  // Columns are 1-based and counted in bytes by the Go side; for the ASCII that MQL
  // is written in they coincide with characters, and clamping keeps a surprise from
  // throwing rather than underlining slightly the wrong thing.
  return Math.min(l.from + Math.max(0, col - 1), l.to)
}

/** Underline to the end of the current word, so the mark has some width. */
function wordEnd(view: EditorView, from: number): number {
  const text = view.state.doc.sliceString(from, Math.min(from + 64, view.state.doc.length))
  const m = /^[A-Za-z0-9_.$]+/.exec(text)
  return from + Math.max(1, m ? m[0].length : 1)
}

export function mqlLinter(kind: 'rule' | 'query') {
  return async (view: EditorView): Promise<Diagnostic[]> => {
    const source = view.state.doc.toString()
    if (!source.trim()) return []

    let res: ValidateResponse
    try {
      res = await api.post<ValidateResponse>('/validate', { source, type: kind })
    } catch (e) {
      // A checker that is unreachable must not paint the document red. Say it once,
      // at the top, and leave the text alone.
      return [
        {
          from: 0,
          to: Math.min(1, view.state.doc.length),
          severity: 'info',
          message: `Could not reach the checker: ${e instanceof Error ? e.message : String(e)}`,
        },
      ]
    }

    if (res.success || res.valid) return []

    const raw = res.error ?? 'this expression was rejected'
    const m = AT.exec(raw)
    if (!m) {
      return [{ from: 0, to: view.state.doc.length, severity: 'error', message: raw }]
    }

    const from = offsetOf(view, Number(m[1]), Number(m[2]))
    return [
      {
        from,
        to: wordEnd(view, from),
        severity: 'error',
        message: m[3] ?? raw,
      },
    ]
  }
}

/** What the expression will need at run time, for the status line under the editor. */
export async function mqlRequirements(source: string, kind: 'rule' | 'query') {
  if (!source.trim()) return null
  try {
    const res = await api.post<ValidateResponse>('/validate', { source, type: kind })
    if (!(res.success || res.valid)) return null
    return { needs: res.needs ?? [], lists: res.lists ?? [] }
  } catch {
    return null
  }
}
