// SPDX-License-Identifier: AGPL-3.0-only

import { api } from '@/api/http'

/**
 * The language definition, served by the engine.
 *
 * Fetched rather than written down here. The engine's registry is what actually
 * type-checks a rule, and it differs per deployment — with RDAP enabled it has
 * rdap.ip and rdap.asn, without it does not. An editor with its own hardcoded list
 * would offer functions this engine will reject and hide ones it accepts, which
 * teaches people a language their own installation does not speak.
 */
export interface MqlField {
  kind: string
  /** The object type to descend into, for an object or an array of objects. */
  type?: string
  doc?: string
  optional?: boolean
  enum?: string[]
}

export interface MqlType {
  fields?: Record<string, MqlField>
}

export interface MqlFunc {
  name: string
  params?: string[]
  keywords?: string[]
  variadic?: boolean
  doc?: string
  returns?: string
  /** Set when the function needs enrichment; shown so an author knows the cost. */
  capability?: string
}

export interface MqlSchema {
  root: string
  types: Record<string, MqlType>
  functions: MqlFunc[]
  lists: string[]
  keywords: string[]
}

let cached: Promise<MqlSchema> | null = null

/** The schema, fetched once per page load. */
export function mqlSchema(): Promise<MqlSchema> {
  if (!cached) {
    cached = api.get<MqlSchema>('/mql/schema').catch((e) => {
      // Let a later attempt retry rather than caching the failure forever: the
      // engine may simply have been restarting.
      cached = null
      throw e
    })
  }
  return cached
}

/**
 * Walk a dotted path through the type graph and return the type it lands on.
 *
 * `sender.email.domain` → the Domain type's fields. An array is transparent:
 * `body.links` yields Link, because `any(body.links, .` completes a link's fields
 * and `body.links[0].` wants the same thing.
 */
export function resolvePath(schema: MqlSchema, path: string[]): MqlType | null {
  let current = schema.types[schema.root]
  for (const segment of path) {
    if (!current?.fields) return null
    const field: MqlField | undefined = current.fields[segment]
    if (!field?.type) return null
    current = schema.types[field.type]
  }
  return current ?? null
}
