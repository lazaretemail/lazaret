// SPDX-License-Identifier: AGPL-3.0-only

package mql

import "sync"

// syncMap is a small typed wrapper over sync.Map, used for the compiled-pattern and
// parsed-CIDR caches. Those are read on every message and written once per distinct rule,
// which is exactly the access pattern sync.Map is built for.
type syncMap[K comparable, V any] struct{ m sync.Map }

func newSyncMap[K comparable, V any]() *syncMap[K, V] { return &syncMap[K, V]{} }

func (s *syncMap[K, V]) Load(k K) (V, bool) {
	v, ok := s.m.Load(k)
	if !ok {
		var zero V
		return zero, false
	}
	return v.(V), true
}

func (s *syncMap[K, V]) Store(k K, v V) { s.m.Store(k, v) }
