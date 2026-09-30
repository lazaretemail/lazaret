// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"strconv"
	"strings"
)

// What the container is allowed to use, and what it is using.
//
// Reused browsers make memory a first-class concern in a way a process per render
// never did: a process that exits gives everything back, and one that stays up
// does not. Measured on a 2GiB container under real mail, a single link browser
// rose from 1.36GiB to 1.91GiB in under two minutes. Nothing here is a leak in
// our code — Chromium simply grows across pages — so the answer is to notice and
// recycle rather than to look for the leak.
//
// Read from the cgroup rather than from runtime.MemStats, because the Go heap is
// a rounding error next to the browsers and it is the *cgroup* that gets killed.
const (
	cgroupV2Max     = "/sys/fs/cgroup/memory.max"
	cgroupV2Current = "/sys/fs/cgroup/memory.current"
	cgroupV1Max     = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
	cgroupV1Current = "/sys/fs/cgroup/memory/memory.usage_in_bytes"
)

// memoryLimit is the container's memory cap in bytes, or 0 when it is unlimited
// or unreadable — which is the case on a plain host, and the reason every caller
// has to have an answer for 0 rather than treating it as "no memory".
func memoryLimit() int64 {
	for _, p := range []string{cgroupV2Max, cgroupV1Max} {
		n, ok := readCgroupBytes(p)
		if !ok {
			continue
		}
		// cgroup v1 spells "unlimited" as a number so large it is meaningless;
		// v2 spells it "max", which readCgroupBytes has already rejected.
		if n <= 0 || n > 1<<50 {
			return 0
		}
		return n
	}
	return 0
}

// memoryUsed is the container's current usage in bytes, or 0 if unreadable.
func memoryUsed() int64 {
	for _, p := range []string{cgroupV2Current, cgroupV1Current} {
		if n, ok := readCgroupBytes(p); ok {
			return n
		}
	}
	return 0
}

func readCgroupBytes(path string) (int64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
