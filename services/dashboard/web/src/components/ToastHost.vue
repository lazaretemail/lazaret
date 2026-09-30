<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { useToasts, dismiss } from '@/composables/toast'
const toasts = useToasts()
</script>

<template>
  <!--
    aria-live so a screen reader announces a failed action. Without it the only
    feedback for "quarantine refused" is a visual box that never gets read out.
  -->
  <div class="host" role="status" aria-live="polite">
    <div v-for="t in toasts" :key="t.id" :class="['toast', t.kind === 'err' ? 'err' : 'note']">
      <span>{{ t.text }}</span>
      <button class="x" aria-label="Dismiss" @click="dismiss(t.id)">×</button>
    </div>
  </div>
</template>

<style scoped>
.host {
  position: fixed;
  right: 1rem;
  bottom: 1rem;
  z-index: 50;
  display: flex;
  flex-direction: column;
  gap: .5rem;
  max-width: min(32rem, calc(100vw - 2rem));
}
.toast {
  display: flex;
  gap: .75rem;
  align-items: flex-start;
  box-shadow: var(--shadow);
  background: var(--panel);
}
.x {
  background: none;
  border: none;
  color: inherit;
  padding: 0;
  line-height: 1;
  font-size: 1.1rem;
  cursor: pointer;
}
.x:hover { background: none; }
</style>
