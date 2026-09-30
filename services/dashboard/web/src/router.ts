// SPDX-License-Identifier: AGPL-3.0-only

import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'

// Paths match the server-rendered console they replace, so existing bookmarks and
// links in tickets keep resolving.
const routes: RouteRecordRaw[] = [
  { path: '/', redirect: '/triage' },
  { path: '/auth/login', name: 'login', component: () => import('@/views/LoginView.vue'), meta: { anon: true } },

  { path: '/overview', name: 'overview', component: () => import('@/views/OverviewView.vue') },
  { path: '/triage', name: 'triage', component: () => import('@/views/TriageView.vue') },
  { path: '/messages/:id', name: 'message', component: () => import('@/views/MessageView.vue'), props: true },

  { path: '/search', name: 'search', component: () => import('@/views/SearchView.vue') },
  { path: '/hunt', name: 'hunt', component: () => import('@/views/HuntView.vue') },
  { path: '/analyzer', name: 'analyzer', component: () => import('@/views/AnalyzerView.vue') },

  // Mail that had already been delivered when we learned something about it, and mail
  // that arrived as one attack rather than thirty.
  { path: '/findings', name: 'findings', component: () => import('@/views/FindingsView.vue') },
  { path: '/campaigns', name: 'campaigns', component: () => import('@/views/CampaignsView.vue') },

  { path: '/detections', name: 'rules', component: () => import('@/views/RulesView.vue') },
  { path: '/detections/effectiveness', name: 'effectiveness', component: () => import('@/views/EffectivenessView.vue') },
  { path: '/detections/coverage', name: 'coverage', component: () => import('@/views/CoverageView.vue') },
  { path: '/detections/backtest', name: 'backtest', component: () => import('@/views/BacktestView.vue') },
  { path: '/detections/:id', name: 'rule', component: () => import('@/views/RuleView.vue'), props: true },

  { path: '/settings/org', name: 'org', component: () => import('@/views/settings/OrgView.vue'), meta: { admin: true } },
  { path: '/settings/mailboxes', name: 'mailboxes', component: () => import('@/views/settings/MailboxesView.vue'), meta: { admin: true } },
  { path: '/settings/actions', name: 'actions', component: () => import('@/views/settings/ActionsView.vue'), meta: { admin: true } },
  { path: '/settings/microsoft', name: 'microsoft', component: () => import('@/views/settings/MicrosoftView.vue'), meta: { admin: true } },
  { path: '/settings/history', name: 'history', component: () => import('@/views/settings/HistoryView.vue'), meta: { admin: true } },
  { path: '/settings/feeds', name: 'feeds', component: () => import('@/views/settings/FeedsView.vue'), meta: { admin: true } },
  { path: '/settings/lists', name: 'lists', component: () => import('@/views/settings/ListsView.vue'), meta: { admin: true } },
  { path: '/settings/lists/:name', name: 'list', component: () => import('@/views/settings/ListView.vue'), props: true, meta: { admin: true } },
  { path: '/settings/learning', name: 'learning', component: () => import('@/views/settings/LearningView.vue'), meta: { admin: true } },
  { path: '/settings/users', name: 'users', component: () => import('@/views/settings/UsersView.vue'), meta: { admin: true } },

  { path: '/:pathMatch(.*)*', name: 'notfound', component: () => import('@/views/NotFoundView.vue') },
]

export const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior(to, from, saved) {
    // Returning to a queue should land where it was left, but changing the filter on
    // the same route should not scroll back up.
    if (saved) return saved
    if (to.path === from.path) return false
    return { top: 0 }
  },
})
