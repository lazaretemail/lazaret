// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it } from 'vitest'
import { loginRedirectTarget } from '../api/http'

describe('loginRedirectTarget', () => {
  it('sends an unauthenticated page to sign in, remembering where it was', () => {
    expect(loginRedirectTarget('/triage', '?state=unreviewed')).toBe(
      '/auth/login?next=%2Ftriage%3Fstate%3Dunreviewed',
    )
  })

  // The sign-in page asks for the session on mount to see whether someone is already
  // signed in. Redirecting that 401 to the sign-in page mounts it again, which asks
  // again: a reload loop on the one page every user has to get through.
  it('does not redirect the sign-in page to itself', () => {
    expect(loginRedirectTarget('/auth/login', '')).toBeNull()
    expect(loginRedirectTarget('/auth/login', '?next=%2Ftriage')).toBeNull()
  })
})
