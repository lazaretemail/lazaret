<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
/**
 * The lazaret mark: a 2×2 grid where three cells match and the fourth does not.
 *
 * The three squares take `currentColor` rather than a fixed ink, so the mark follows
 * the surface it sits on and needs no separate reversed copy for light and dark. The
 * diamond keeps its amber in every variant — it is the whole point of the mark, and
 * a flag that changes colour with the theme is not a flag.
 */
withDefaults(defineProps<{ size?: number | string; title?: string }>(), {
  size: 24,
  title: '',
})
</script>

<template>
  <svg
    :width="size"
    :height="size"
    viewBox="0 0 100 100"
    :role="title ? 'img' : 'presentation'"
    :aria-label="title || undefined"
    :aria-hidden="title ? undefined : 'true'"
    focusable="false"
  >
    <rect x="14" y="14" width="30" height="30" fill="currentColor" />
    <rect x="56" y="14" width="30" height="30" fill="currentColor" />
    <rect x="14" y="56" width="30" height="30" fill="currentColor" />
    <path d="M71 54 L88 71 L71 88 L54 71 Z" fill="var(--amber)" />
  </svg>
</template>
