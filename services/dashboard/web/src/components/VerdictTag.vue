<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { verdictClass } from '@/format'
defineProps<{ verdict?: string | null | undefined }>()
</script>

<template>
  <span :class="['tag', verdictClass(verdict)]">{{ verdict || 'unknown' }}</span>
</template>
