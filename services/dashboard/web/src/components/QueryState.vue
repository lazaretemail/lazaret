<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
/**
 * One place where loading, failure and emptiness are drawn.
 *
 * The server-rendered console this replaces had no such place: each page decided for
 * itself, and the pages that forgot rendered a plausible-looking empty table whether
 * the query returned nothing or the backend was unreachable. Those two things look
 * identical to a reader and mean opposite things to an operator. Routing every view
 * through this component makes "no results" and "no answer" impossible to confuse.
 */
withDefaults(
  defineProps<{
    loading?: boolean | undefined
    error?: unknown
    empty?: boolean | undefined
    emptyText?: string | undefined
    /** Keep showing stale content while a background refetch runs. */
    hasData?: boolean | undefined
  }>(),
  { emptyText: 'Nothing to show.' },
)

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}
function detail(e: unknown): string | undefined {
  return (e as { detail?: string })?.detail
}
</script>

<template>
  <div v-if="error" class="err">
    <strong>This could not be loaded.</strong>
    {{ message(error) }}
    <pre v-if="detail(error)" class="detail mono">{{ detail(error) }}</pre>
  </div>

  <div v-else-if="loading && !hasData" class="skeleton" aria-busy="true">
    <span class="sr-only">Loading</span>
    <div v-for="i in 4" :key="i" class="bar" />
  </div>

  <div v-else-if="empty" class="empty">{{ emptyText }}</div>

  <slot v-else />
</template>

<style scoped>
.detail {
  margin: .5rem 0 0;
  max-height: 12rem;
  overflow: auto;
  white-space: pre-wrap;
  opacity: .85;
}
.skeleton { display: flex; flex-direction: column; gap: .5rem; padding: .5rem 0; }
.bar {
  height: 1.6rem;
  border-radius: 4px;
  background: linear-gradient(90deg, var(--panel) 25%, var(--panel-2) 50%, var(--panel) 75%);
  background-size: 200% 100%;
  animation: shimmer 1.2s linear infinite;
}
@keyframes shimmer {
  from { background-position: 200% 0; }
  to { background-position: -200% 0; }
}
</style>
