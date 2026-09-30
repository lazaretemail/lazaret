// SPDX-License-Identifier: AGPL-3.0-only
//
// The one place the console talks to its backend.
//
// Every call goes to the dashboard's own /api, never to the engine directly. The
// browser holds a session cookie; only the dashboard holds an engine credential. That
// separation is what keeps mailbox and Graph secrets — which the engine will hand to a
// service token — unreachable from a page.

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly detail?: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

/**
 * The CSRF token, read fresh from the cookie on every request.
 *
 * Deliberately not cached: the server reissues it whenever the session changes, and a
 * stale copy held in a module variable would start failing after a re-login with no
 * visible cause.
 */
function csrfToken(): string {
  const hit = document.cookie.split('; ').find((c) => c.startsWith('lazaret_csrf='))
  return hit ? decodeURIComponent(hit.slice('lazaret_csrf='.length)) : ''
}

export const LOGIN_PATH = '/auth/login'

/**
 * Where a 401 should send the viewer, or null to stay put.
 *
 * Null on the sign-in page itself, and that case is the whole reason this is a
 * separate function. The sign-in page asks for the session on mount to find out
 * whether someone is already signed in; without this guard that 401 redirected it
 * to itself, which mounted it again, which asked again — an unbreakable reload loop
 * on the one page every user has to get through.
 */
export function loginRedirectTarget(pathname: string, search: string): string | null {
  if (pathname === LOGIN_PATH) return null
  return `${LOGIN_PATH}?next=${encodeURIComponent(pathname + search)}`
}

/** Send the viewer to sign in, remembering where they were. */
function toLogin(): never {
  const to = loginRedirectTarget(location.pathname, location.search)
  if (to) location.assign(to)
  // location.assign does not stop execution; this keeps callers from treating the
  // aborted request as data.
  throw new ApiError(401, 'signing in')
}

type Params = Record<string, string | number | boolean | undefined | null>

function withQuery(path: string, params?: Params): string {
  if (!params) return path
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') q.set(k, String(v))
  }
  const s = q.toString()
  return s ? `${path}?${s}` : path
}

async function request<T>(method: string, path: string, body?: unknown, params?: Params): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken()

  const res = await fetch(withQuery(`/api${path}`, params), {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? null : JSON.stringify(body),
  })

  if (res.status === 401) toLogin()
  if (res.status === 204) return undefined as T

  const text = await res.text()
  let parsed: unknown
  try {
    parsed = text ? JSON.parse(text) : null
  } catch {
    // An HTML error page or a proxy timeout. Surfacing the raw body would put a page
    // of markup in a toast, so report the status and keep the body for the console.
    if (!res.ok) throw new ApiError(res.status, `the server returned ${res.status}`, text.slice(0, 2000))
    throw new ApiError(res.status, 'the server sent a response that was not JSON', text.slice(0, 2000))
  }

  if (!res.ok) {
    const e = parsed as { error?: string; detail?: string } | null
    throw new ApiError(res.status, e?.error || `the server returned ${res.status}`, e?.detail)
  }
  return parsed as T
}

export const api = {
  get: <T>(path: string, params?: Params) => request<T>('GET', path, undefined, params),
  post: <T>(path: string, body?: unknown, params?: Params) => request<T>('POST', path, body, params),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body),
  patch: <T>(path: string, body?: unknown) => request<T>('PATCH', path, body),
  del: <T>(path: string, body?: unknown) => request<T>('DELETE', path, body),
}

/** Upload a file, which cannot go as JSON. Used by the analyzer's .eml drop. */
export async function upload<T>(path: string, form: FormData): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method: 'POST',
    headers: { Accept: 'application/json', 'X-CSRF-Token': csrfToken() },
    credentials: 'same-origin',
    body: form,
  })
  if (res.status === 401) toLogin()
  const text = await res.text()
  const parsed = text ? JSON.parse(text) : null
  if (!res.ok) {
    const e = parsed as { error?: string } | null
    throw new ApiError(res.status, e?.error || `the server returned ${res.status}`)
  }
  return parsed as T
}
