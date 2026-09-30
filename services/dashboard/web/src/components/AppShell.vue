<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/api/http'
import { useSession, can } from '@/composables/session'
import { toast } from '@/composables/toast'
import LazaretMark from '@/components/LazaretMark.vue'

const { data: session, isError } = useSession()
const router = useRouter()
const open = ref(false)

const user = computed(() => session.value?.user)
const counts = computed(() => session.value?.counts ?? {})
const isAdmin = computed(() => can(user.value?.role, 'admin'))

async function signOut() {
  try {
    await api.post('/auth/logout')
  } catch (e) {
    toast.err(e)
  }
  // A full load rather than a route push: it drops every cached query with the
  // session that authorised it, so the next person to use this browser starts clean.
  location.assign('/auth/login')
}

const queues = computed(() => session.value?.queues ?? [])
function badge(key: string): number {
  return counts.value[key] ?? 0
}

function go(path: string) {
  open.value = false
  router.push(path)
}
</script>

<template>
  <div class="shell" :class="{ open }">
    <button class="burger" aria-label="Menu" @click="open = !open">☰</button>

    <aside>
      <RouterLink class="brand" to="/overview" aria-label="lazaret — overview">
        <LazaretMark :size="26" />
        <span class="wordmark">lazaret</span>
      </RouterLink>

      <nav>
        <div class="group">
          <span class="grouplabel">Monitor</span>
          <a href="#" :class="{ on: $route.name === 'overview' }" @click.prevent="go('/overview')">Overview</a>
        </div>

        <div class="group">
          <span class="grouplabel">Triage</span>
          <a
            v-for="q in queues"
            :key="q.key"
            href="#"
            :title="q.hint"
            :class="{ on: $route.name === 'triage' && ($route.query.state || 'needs_remediation') === q.key }"
            @click.prevent="go(`/triage?state=${q.key}`)"
          >
            {{ q.label }}
            <span v-if="badge(q.key) > 0" class="count" :class="{ bad: q.key === 'needs_remediation' }">
              {{ badge(q.key) }}
            </span>
          </a>
        </div>

        <div class="group">
          <span class="grouplabel">Investigate</span>
          <a href="#" :class="{ on: $route.name === 'search' }" @click.prevent="go('/search')">Search</a>
          <a href="#" :class="{ on: $route.name === 'hunt' }" @click.prevent="go('/hunt')">Hunt</a>
          <a href="#" :class="{ on: $route.name === 'analyzer' }" @click.prevent="go('/analyzer')">Analyzer</a>
          <a href="#" :class="{ on: $route.name === 'campaigns' }" @click.prevent="go('/campaigns')">Campaigns</a>
          <a href="#" :class="{ on: $route.name === 'findings' }" @click.prevent="go('/findings')">
            Found later
            <span v-if="badge('findings') > 0" class="count">{{ badge('findings') }}</span>
          </a>
        </div>

        <div class="group">
          <span class="grouplabel">Detections</span>
          <a href="#" :class="{ on: ['rules', 'rule'].includes(String($route.name)) }" @click.prevent="go('/detections')">Rules</a>
          <a href="#" :class="{ on: $route.name === 'effectiveness' }" @click.prevent="go('/detections/effectiveness')">Effectiveness</a>
          <a href="#" :class="{ on: $route.name === 'coverage' }" @click.prevent="go('/detections/coverage')">Coverage</a>
          <a href="#" :class="{ on: $route.name === 'backtest' }" @click.prevent="go('/detections/backtest')">Backtest</a>
        </div>

        <div v-if="isAdmin" class="group">
          <span class="grouplabel">Settings</span>
          <a href="#" :class="{ on: $route.name === 'org' }" @click.prevent="go('/settings/org')">Organisation</a>
          <a href="#" :class="{ on: $route.name === 'mailboxes' }" @click.prevent="go('/settings/mailboxes')">Mailboxes</a>
          <a href="#" :class="{ on: $route.name === 'actions' }" @click.prevent="go('/settings/actions')">Actions</a>
          <a href="#" :class="{ on: $route.name === 'microsoft' }" @click.prevent="go('/settings/microsoft')">Microsoft 365</a>
          <a href="#" :class="{ on: $route.name === 'history' }" @click.prevent="go('/settings/history')">History scans</a>
          <a href="#" :class="{ on: $route.name === 'feeds' }" @click.prevent="go('/settings/feeds')">Rule feeds</a>
          <a href="#" :class="{ on: ['lists', 'list'].includes(String($route.name)) }" @click.prevent="go('/settings/lists')">Lists</a>
          <a href="#" :class="{ on: $route.name === 'learning' }" @click.prevent="go('/settings/learning')">Learning</a>
          <a href="#" :class="{ on: $route.name === 'users' }" @click.prevent="go('/settings/users')">Users &amp; tokens</a>
        </div>
      </nav>

      <div class="who">
        <div class="mono">{{ user?.email }}</div>
        <div class="dim">
          {{ user?.role }}<template v-if="session?.read_only"> · read-only</template>
        </div>
        <button class="link" type="button" @click="signOut">Sign out</button>
      </div>
    </aside>

    <main>
      <div v-if="isError" class="err" style="margin-bottom: 1rem">
        The console cannot reach its backend. Pages below may be stale.
      </div>
      <slot />
    </main>
  </div>
</template>

<style scoped>
.shell {
  display: grid;
  grid-template-columns: var(--sidebar) minmax(0, 1fr);
  min-height: 100%;
}

aside {
  border-right: 1px solid var(--line);
  background: var(--panel);
  padding: 1rem .75rem 1.25rem;
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
  position: sticky;
  top: 0;
  height: 100vh;
  overflow-y: auto;
}

.brand {
  display: flex;
  align-items: center;
  gap: .55rem;
  padding: 0 .5rem;
  color: var(--fg);
}
.brand .wordmark { font-size: 1.35rem; }
.brand:hover { text-decoration: none; }

nav { display: flex; flex-direction: column; gap: 1.1rem; }
.group { display: flex; flex-direction: column; gap: .05rem; }
.grouplabel {
  font-size: .68rem;
  text-transform: uppercase;
  letter-spacing: .07em;
  color: var(--faint);
  padding: 0 .5rem .25rem;
}

nav a {
  color: var(--dim);
  padding: .3rem .5rem;
  border-radius: 4px;
  display: flex;
  align-items: center;
  gap: .5rem;
  font-size: .9rem;
}
nav a:hover { background: var(--panel-2); text-decoration: none; color: var(--fg); }
nav a.on { color: var(--fg); background: var(--panel-2); font-weight: 500; }

.count {
  margin-left: auto;
  font-size: .72rem;
  font-variant-numeric: tabular-nums;
  color: var(--dim);
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 999px;
  padding: 0 .4rem;
}
.count.bad { color: var(--bad); border-color: color-mix(in srgb, var(--bad) 50%, transparent); }

.who {
  margin-top: auto;
  padding: .75rem .5rem 0;
  border-top: 1px solid var(--line);
  font-size: .8rem;
  display: flex;
  flex-direction: column;
  gap: .15rem;
  align-items: flex-start;
}

main {
  padding: 1.5rem 1.75rem 5rem;
  max-width: 1500px;
  min-width: 0;
}

.burger { display: none; }

@media (max-width: 900px) {
  .shell { grid-template-columns: minmax(0, 1fr); }
  aside {
    position: fixed;
    inset: 0 auto 0 0;
    width: var(--sidebar);
    z-index: 40;
    transform: translateX(-100%);
    transition: transform .15s ease;
    box-shadow: var(--shadow);
  }
  .shell.open aside { transform: none; }
  .burger {
    display: block;
    position: fixed;
    top: .6rem;
    left: .6rem;
    z-index: 45;
  }
  main { padding: 3.25rem 1rem 4rem; }
}
</style>
