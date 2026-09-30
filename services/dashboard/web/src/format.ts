// SPDX-License-Identifier: AGPL-3.0-only
//
// Display formatting. These were template functions in the server-rendered console;
// in the browser they can use the viewer's own locale and time zone, which is what
// an analyst actually wants when correlating against a log on their own machine.

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ['second', 1000],
  ['minute', 60_000],
  ['hour', 3_600_000],
  ['day', 86_400_000],
]

/** "3 hours ago". Falls back to a date once it stops being a useful relative claim. */
export function ago(value?: string | null): string {
  if (!value) return ''
  const t = new Date(value)
  if (Number.isNaN(t.getTime()) || t.getFullYear() < 1971) return ''
  const diff = t.getTime() - Date.now()
  const abs = Math.abs(diff)
  if (abs > 30 * 86_400_000) return t.toLocaleDateString(undefined, { dateStyle: 'medium' })
  let unit: Intl.RelativeTimeFormatUnit = 'second'
  let size = 1000
  for (const [u, ms] of UNITS) {
    if (abs >= ms) {
      unit = u
      size = ms
    }
  }
  return rtf.format(Math.round(diff / size), unit)
}

/** An absolute timestamp, for the places where "2 days ago" is not precise enough. */
export function stamp(value?: string | null): string {
  if (!value) return ''
  const t = new Date(value)
  if (Number.isNaN(t.getTime()) || t.getFullYear() < 1971) return ''
  return t.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

/** The full ISO form, for a title attribute next to a relative one. */
export function iso(value?: string | null): string {
  if (!value) return ''
  const t = new Date(value)
  return Number.isNaN(t.getTime()) ? '' : t.toISOString()
}

export function short(s: string | undefined | null, n: number): string {
  if (!s) return ''
  return s.length <= n ? s : s.slice(0, n) + '…'
}

export function count(n: number | undefined | null): string {
  return (n ?? 0).toLocaleString()
}

/** Severity and verdict both map onto the same four-colour vocabulary. */
export function verdictClass(v?: string | null): string {
  switch (v) {
    case 'malicious':
      return 'bad'
    case 'indeterminate':
      return 'unknown'
    case 'clean':
      return 'ok'
    default:
      return 'mute'
  }
}

/**
 * A slice that Go may have sent as null.
 *
 * `encoding/json` writes a nil slice as `null`, not `[]`, while the generated
 * TypeScript declares it `T[]` — so any `.length` or `.map` on one throws, Vue
 * abandons the rest of that subtree, and the page renders a convincing blank where
 * the data should be. That is the same silent-partial-render failure the templates
 * had, wearing a different hat.
 *
 * Wrapping every array read from the wire in this makes the miss a miss. It is
 * deliberately a named function rather than a scattering of `?? []` so the reason is
 * greppable and the habit is visible in review.
 */
export function arr<T>(v: readonly T[] | null | undefined): readonly T[] {
  return v ?? []
}
