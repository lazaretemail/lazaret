// SPDX-License-Identifier: AGPL-3.0-only

import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'

/**
 * The time window, held in the URL rather than in component state.
 *
 * So that a view of a particular window is a link somebody can paste into a ticket,
 * and so that Back goes where it looks like it should. A local ref would also have
 * silently ignored a ?window= that someone typed or shared.
 */
export function useUrlWindow(fallback = '30') {
  const route = useRoute()
  const router = useRouter()
  return computed<string>({
    get: () => String(route.query.window ?? fallback),
    set: (v) => {
      router.replace({ query: { ...route.query, window: v } })
    },
  })
}
