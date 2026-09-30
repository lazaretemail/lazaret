<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
defineProps<{ title: string; hint?: string | undefined }>()
</script>

<template>
  <header class="head">
    <div>
      <h1>{{ title }}</h1>
      <p v-if="hint" class="dim">{{ hint }}</p>
    </div>
    <div class="row"><slot name="actions" /></div>
  </header>
</template>

<style scoped>
.head {
  display: flex;
  gap: 1rem;
  align-items: flex-start;
  justify-content: space-between;
  flex-wrap: wrap;
  margin-bottom: 1.25rem;
}
.head p { font-size: .88rem; margin: 0; }
</style>
