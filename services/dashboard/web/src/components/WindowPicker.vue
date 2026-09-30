<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
const model = defineModel<string>({ default: '30' })

// "Everything" is a real option: an archive evaluated after the fact has messages
// dated years ago, and a window that silently excludes them looks like no data.
const OPTIONS: [string, string][] = [
  ['1', 'last 24 hours'],
  ['7', 'last 7 days'],
  ['30', 'last 30 days'],
  ['90', 'last 90 days'],
  ['365', 'last year'],
  ['all', 'everything'],
]
</script>

<template>
  <select v-model="model" aria-label="Time window">
    <option v-for="[value, label] in OPTIONS" :key="value" :value="value">{{ label }}</option>
  </select>
</template>
