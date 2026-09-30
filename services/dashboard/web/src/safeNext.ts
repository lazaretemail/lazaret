// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Where to go after signing in, refusing anything that leaves this origin.
 *
 * The sign-in page takes a `next` from its own query string, so without this an
 * attacker can hand someone `/auth/login?next=https://evil.test` — a link that
 * genuinely starts at the security console, shows a genuine sign-in form, and then
 * lands them somewhere else. That is a good phishing lure precisely because the
 * first hop is trustworthy.
 *
 * Parsed rather than prefix-checked. A prefix test for "/" lets through
 * "/\\evil.test", which several browsers normalise to "//evil.test" — a
 * protocol-relative URL. Backslashes and control bytes are refused outright, since
 * no legitimate path here has one.
 */
export function safeNext(raw: string | null | undefined): string {
  if (!raw) return '/'
  if (/[\\\r\n\0]/.test(raw)) return '/'
  let u: URL
  try {
    u = new URL(raw, location.origin)
  } catch {
    return '/'
  }
  if (u.origin !== location.origin) return '/'
  if (!u.pathname.startsWith('/') || u.pathname.startsWith('//')) return '/'
  return u.pathname + u.search + u.hash
}
