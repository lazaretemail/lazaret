// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it, beforeAll } from 'vitest'
import { safeNext } from '../safeNext'

beforeAll(() => {
  // safeNext compares against the page's own origin, so the test needs one.
  Object.defineProperty(globalThis, 'location', {
    value: new URL('https://console.example.test/auth/login'),
    writable: true,
  })
})

describe('safeNext', () => {
  it('keeps a local path', () => {
    expect(safeNext('/triage?state=unreviewed')).toBe('/triage?state=unreviewed')
  })

  it('defaults when absent', () => {
    expect(safeNext(null)).toBe('/')
    expect(safeNext('')).toBe('/')
  })

  it.each([
    ['https://evil.test/', 'an absolute URL elsewhere'],
    ['//evil.test/', 'a protocol-relative URL'],
    ['/\\evil.test', 'a backslash some browsers normalise to //'],
    ['javascript:alert(1)', 'a script scheme'],
    ['/ok\r\nLocation: https://evil.test', 'a header injection attempt'],
  ])('refuses %s (%s)', (input) => {
    expect(safeNext(input)).toBe('/')
  })
})
