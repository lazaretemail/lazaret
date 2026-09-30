// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it } from 'vitest'
import { resolvePath, type MqlSchema } from '../mql/schema'

// A miniature of what the engine serves, with the shapes that matter: a nested
// object path, an array of objects, and a cycle (a Message inside a Message, which
// file.parse_eml really does return).
const schema: MqlSchema = {
  root: 'Message',
  types: {
    Message: {
      fields: {
        sender: { kind: 'object', type: 'Sender' },
        body: { kind: 'object', type: 'Body' },
        subject: { kind: 'object', type: 'Subject' },
        parsed: { kind: 'object', type: 'Message' },
      },
    },
    Sender: { fields: { email: { kind: 'object', type: 'Email' } } },
    Email: {
      fields: {
        email: { kind: 'string' },
        domain: { kind: 'object', type: 'Domain' },
      },
    },
    Domain: { fields: { root_domain: { kind: 'string' }, tld: { kind: 'string' } } },
    Body: { fields: { links: { kind: 'array', type: 'Link' } } },
    Link: { fields: { href_url: { kind: 'object', type: 'Url' }, display_text: { kind: 'string' } } },
    Url: { fields: { domain: { kind: 'object', type: 'Domain' } } },
    Subject: { fields: { subject: { kind: 'string' } } },
  },
  functions: [],
  lists: [],
  keywords: [],
}

describe('resolvePath', () => {
  it('walks a nested field path', () => {
    const t = resolvePath(schema, ['sender', 'email', 'domain'])
    expect(Object.keys(t?.fields ?? {}).sort()).toEqual(['root_domain', 'tld'])
  })

  // `any(body.links, .href_url…)` is the single most common shape in the corpus.
  // Completion has to see through the array to the element type or it gives up on
  // most of what anyone writes.
  it('sees through an array to its element type', () => {
    const t = resolvePath(schema, ['body', 'links'])
    expect(Object.keys(t?.fields ?? {}).sort()).toEqual(['display_text', 'href_url'])
  })

  it('walks through an array element into a further object', () => {
    const t = resolvePath(schema, ['body', 'links', 'href_url', 'domain'])
    expect(Object.keys(t?.fields ?? {})).toContain('root_domain')
  })

  // The MDM is recursive. Resolution must terminate rather than chase the cycle.
  it('handles a type that contains itself', () => {
    const t = resolvePath(schema, ['parsed', 'parsed', 'sender', 'email'])
    expect(Object.keys(t?.fields ?? {})).toContain('domain')
  })

  it('returns null for a path that does not exist', () => {
    expect(resolvePath(schema, ['sender', 'emial'])).toBeNull()
    expect(resolvePath(schema, ['nope'])).toBeNull()
  })

  // A primitive has no fields; offering completions after `.root_domain.` would be
  // suggesting members of a string.
  it('returns null past a primitive', () => {
    expect(resolvePath(schema, ['sender', 'email', 'domain', 'root_domain'])).toBeNull()
  })

  it('returns the root for an empty path', () => {
    const t = resolvePath(schema, [])
    expect(Object.keys(t?.fields ?? {})).toContain('sender')
  })
})
