<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import type { DomainInfo } from '@/api/types.gen'
import { arr, count } from '@/format'

const props = defineProps<{ info: DomainInfo; domain?: string | undefined }>()

// A domain registered days ago is the single strongest cheap signal there is, so it
// gets called out rather than being one row among many.
const young = () => props.info.domain_age_days !== undefined && props.info.domain_age_days < 30
</script>

<template>
  <dl class="summary">
    <template v-if="domain">
      <dt>Domain</dt>
      <dd class="mono">{{ domain }}</dd>
    </template>

    <template v-if="info.looked_up && info.looked_up !== domain">
      <dt>Looked up</dt>
      <dd class="mono">{{ info.looked_up }}</dd>
    </template>

    <dt>Registered</dt>
    <dd v-if="!info.domain_known" class="faint">unknown — no registry answer</dd>
    <dd v-else-if="!info.domain_registered" class="warn-text">not registered</dd>
    <dd v-else-if="info.domain_age_days !== undefined" :class="{ 'warn-text': young() }">
      {{ count(info.domain_age_days) }} days ago
    </dd>
    <dd v-else>yes</dd>

    <template v-if="info.registrar">
      <dt>Registrar</dt>
      <dd>{{ info.registrar }}</dd>
    </template>
    <template v-if="info.registrant_company">
      <dt>Registrant</dt>
      <dd>{{ info.registrant_company }}</dd>
    </template>
    <template v-if="info.registrant_country">
      <dt>Country</dt>
      <dd>{{ info.registrant_country }}</dd>
    </template>
    <template v-if="info.registrant_email">
      <dt>Abuse contact</dt>
      <dd class="mono">{{ info.registrant_email }}</dd>
    </template>
    <template v-if="arr(info.name_servers).length">
      <dt>Name servers</dt>
      <dd class="mono">{{ arr(info.name_servers).join(', ') }}</dd>
    </template>
  </dl>
</template>

<style scoped>
.warn-text { color: var(--unknown); }
</style>
