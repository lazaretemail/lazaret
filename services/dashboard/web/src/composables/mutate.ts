// SPDX-License-Identifier: AGPL-3.0-only

import { useMutation, useQueryClient } from '@tanstack/vue-query'
import { toast } from '@/composables/toast'

/**
 * A settings mutation: call it, say so, refetch what it changed.
 *
 * Every settings page did these three things by hand, and the ones that forgot the
 * refetch showed the old value until the page was reloaded — which reads as "the save
 * did not work" and invites someone to do it twice.
 */
export function useSave<TArgs = void>(opts: {
  run: (args: TArgs) => Promise<unknown>
  done: string
  invalidate: unknown[][]
}) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: opts.run,
    onSuccess: () => {
      toast.ok(opts.done)
      for (const key of opts.invalidate) qc.invalidateQueries({ queryKey: key })
    },
    onError: (e) => toast.err(e),
  })
}
