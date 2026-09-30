<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import type { Insight } from '@/api/types.gen'
import { arr } from '@/format'

defineProps<{ title: string; items: readonly Insight[] }>()

/**
 * Render an insight's value for a person.
 *
 * This was a method on the Go type; in the browser the value arrives as whatever
 * JSON made of it, so the formatting has to happen here. An explicitly unknown fact
 * prints as "unknown" rather than as an empty cell, because a blank reads as "no"
 * and these two mean very different things to whoever is deciding.
 */
function display(i: Insight): string {
  if (i.unknown) return 'unknown'
  const v = i.value
  if (v === null || v === undefined || v === '') return '—'
  if (typeof v === 'boolean') return v ? 'yes' : 'no'
  if (Array.isArray(v)) return v.length ? v.join(', ') : '—'
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}
</script>

<template>
  <section v-if="items.length">
    <h3>{{ title }}</h3>
    <dl class="summary">
      <template v-for="(i, n) in items" :key="n">
        <dt>{{ i.label }}</dt>
        <dd :class="{ flag: i.warn, faint: i.unknown }">
          {{ display(i) }}
          <span v-if="arr(i.missing).length" class="tag mute" :title="`needs ${arr(i.missing).join(', ')}`">
            unavailable
          </span>
        </dd>
      </template>
    </dl>
  </section>
</template>

<style scoped>
/* A fixed label column, because each group is a separate <dl>: sizing them
   independently with max-content left the three sets of labels visibly out of step
   down the page. */
.summary { grid-template-columns: 13rem minmax(0, 1fr); }
@media (max-width: 640px) { .summary { grid-template-columns: minmax(0, 1fr); } }

dd.flag { color: var(--unknown); font-weight: 500; }
section { margin-bottom: 1.25rem; }
</style>
