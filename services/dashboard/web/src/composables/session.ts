// SPDX-License-Identifier: AGPL-3.0-only

import { useQuery, useQueryClient } from '@tanstack/vue-query'
import { api } from '@/api/http'
import type { Bootstrap } from '@/api/types.gen'

/**
 * Who is signed in, what they may do, and the queue depths in the navigation.
 *
 * One query shared by every component that asks: TanStack dedupes by key, so the
 * sidebar, the route guard and a page-level permission check are a single request.
 */
export function useSession() {
  const q = useQuery({
    queryKey: ['session'],
    queryFn: () => api.get<Bootstrap>('/session'),
    // Queue badges going stale is the visible symptom of this being too long.
    staleTime: 15_000,
    refetchInterval: 60_000,
    retry: false,
  })
  return q
}

/** Roles are ordered, so "can admin" implies "can analyst". */
const RANK: Record<string, number> = { viewer: 1, analyst: 2, admin: 3 }

export function can(role: string | undefined, needed: string): boolean {
  return (RANK[role ?? ''] ?? 0) >= (RANK[needed] ?? 99)
}

export function useRefreshSession() {
  const qc = useQueryClient()
  return () => qc.invalidateQueries({ queryKey: ['session'] })
}
