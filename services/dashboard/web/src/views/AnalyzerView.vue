<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { ref } from 'vue'
import { useMutation } from '@tanstack/vue-query'
import { upload } from '@/api/http'
import type { MessagePage } from '@/api/types.gen'
import { toast } from '@/composables/toast'
import PageHead from '@/components/PageHead.vue'
import MessageDetail from '@/components/MessageDetail.vue'

const text = ref('')
const file = ref<File | null>(null)
const result = ref<MessagePage | null>(null)
const dragging = ref(false)

const run = useMutation({
  mutationFn: () => {
    const form = new FormData()
    if (file.value) form.append('file', file.value)
    else form.append('eml', text.value)
    return upload<MessagePage>('/analyze', form)
  },
  onSuccess: (page) => {
    result.value = page
  },
  onError: (e) => toast.err(e),
})

function pick(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0]
  file.value = f ?? null
}

function drop(e: DragEvent) {
  dragging.value = false
  const f = e.dataTransfer?.files?.[0]
  if (f) file.value = f
}

function reset() {
  result.value = null
  file.value = null
  text.value = ''
}
</script>

<template>
  <PageHead
    title="Analyzer"
    hint="Evaluate a message without recording it — nothing here is written to the corpus or builds the sender a history."
  >
    <template #actions>
      <button v-if="result" type="button" @click="reset">Analyse another</button>
    </template>
  </PageHead>

  <form v-if="!result" class="stack" @submit.prevent="run.mutate()">
    <div
      class="drop"
      :class="{ over: dragging }"
      @dragover.prevent="dragging = true"
      @dragleave="dragging = false"
      @drop.prevent="drop"
    >
      <template v-if="file">
        <strong>{{ file.name }}</strong>
        <button class="link" type="button" @click="file = null">remove</button>
      </template>
      <template v-else>
        Drop a <code>.eml</code> here, or
        <label class="pick">
          choose a file
          <input type="file" accept=".eml,message/rfc822,text/plain" @change="pick" />
        </label>
      </template>
    </div>

    <template v-if="!file">
      <label for="eml">…or paste the message source</label>
      <textarea id="eml" v-model="text" rows="12" spellcheck="false" placeholder="From: …&#10;Subject: …" />
    </template>

    <div class="row">
      <button class="primary" type="submit" :disabled="run.isPending.value || (!file && !text.trim())">
        {{ run.isPending.value ? 'Analysing…' : 'Analyse' }}
      </button>
      <span v-if="run.isPending.value" class="dim">
        Rules, enrichment and rendering all run for this — it can take a few seconds.
      </span>
    </div>
  </form>

  <MessageDetail v-else :page="result" />
</template>

<style scoped>
.drop {
  border: 1px dashed var(--line);
  border-radius: var(--r);
  padding: 1.5rem;
  text-align: center;
  color: var(--dim);
  display: flex;
  gap: .5rem;
  align-items: center;
  justify-content: center;
}
.drop.over { border-color: var(--accent); background: color-mix(in srgb, var(--accent) 8%, transparent); }
.pick { display: inline; color: var(--link); cursor: pointer; text-decoration: underline; margin: 0; }
.pick input { display: none; }
code { font-family: var(--mono); font-size: .9em; }
</style>
