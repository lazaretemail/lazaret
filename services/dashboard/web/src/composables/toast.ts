// SPDX-License-Identifier: AGPL-3.0-only

import { ref } from 'vue'

export type Toast = { id: number; kind: 'ok' | 'err'; text: string }

// Module-level so any component can raise one without the shell having to thread a
// prop down to it.
const items = ref<Toast[]>([])
let seq = 0

export function useToasts() {
  return items
}

function push(kind: Toast['kind'], text: string) {
  const id = ++seq
  items.value.push({ id, kind, text })
  // Errors stay long enough to read and copy; confirmations do not need to.
  setTimeout(() => dismiss(id), kind === 'err' ? 9000 : 3500)
}

export function dismiss(id: number) {
  items.value = items.value.filter((t) => t.id !== id)
}

export const toast = {
  ok: (text: string) => push('ok', text),
  err: (e: unknown) => push('err', e instanceof Error ? e.message : String(e)),
}
