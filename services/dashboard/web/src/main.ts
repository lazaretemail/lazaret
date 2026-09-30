// SPDX-License-Identifier: AGPL-3.0-only

import { createApp } from 'vue'
import { VueQueryPlugin, QueryClient } from '@tanstack/vue-query'
// Self-hosted, so the console still loads nothing from anywhere: a Google Fonts
// <link> would mean whitelisting two external origins in the CSP of a page that
// renders attacker-authored subject lines. Both faces are OFL-1.1.
import '@fontsource-variable/space-grotesk'
import '@fontsource/ibm-plex-mono/400.css'
import '@fontsource/ibm-plex-mono/500.css'

import App from './App.vue'
import { router } from './router'
import './styles/base.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // A console left open on a second monitor should be showing current data when
      // it is looked at again, without hammering the engine while it is ignored.
      staleTime: 10_000,
      refetchOnWindowFocus: true,
      retry: (failures, error) => {
        // A refused or missing thing will stay refused; only retry what might be a
        // blip. Retrying a 403 three times just delays telling the user.
        const status = (error as { status?: number }).status ?? 0
        if (status >= 400 && status < 500) return false
        return failures < 2
      },
    },
  },
})

createApp(App).use(router).use(VueQueryPlugin, { queryClient }).mount('#app')
