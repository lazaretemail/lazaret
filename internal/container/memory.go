// SPDX-License-Identifier: AGPL-3.0-only

// Package container reads what the cgroup allows this process, so a service can
// size itself to its container rather than to the machine the container is on.
//
// Every library that sizes a cache or a buffer pool from "total RAM" is wrong in
// a compose stack: thirteen containers each helpfully taking most of the host is
// how a deployment ends up with memory pressure nobody can account for. DuckDB in
// particular defaults its memory_limit to 80% of system RAM, which on a 30GB host
// is 24GB for one service that shares the box with twelve others.
package container

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

const (
	v2Max     = "/sys/fs/cgroup/memory.max"
	v2Current = "/sys/fs/cgroup/memory.current"
	v1Max     = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
	v1Current = "/sys/fs/cgroup/memory/memory.usage_in_bytes"
)

// MemoryLimit is the cgroup's memory cap in bytes, or 0 when there is none.
//
// Callers must have an answer for 0: it is what a plain host returns, and also
// what an unlimited container returns, and "no limit" is not "no memory".
func MemoryLimit() int64 {
	for _, p := range []string{v2Max, v1Max} {
		n, ok := readBytes(p)
		if !ok {
			continue
		}
		// v1 spells unlimited as a number so large it is meaningless; v2 spells it
		// "max", which readBytes has already rejected as unparseable.
		if n <= 0 || n > 1<<50 {
			return 0
		}
		return n
	}
	return 0
}

// MemoryUsed is the cgroup's current usage in bytes, or 0 if unreadable.
//
// This counts page cache as well as anonymous memory, which is why a container
// doing file I/O sits near its limit without being in any trouble. Use it for
// pressure, not for "how much does this need".
func MemoryUsed() int64 {
	for _, p := range []string{v2Current, v1Current} {
		if n, ok := readBytes(p); ok {
			return n
		}
	}
	return 0
}

// Budget is a share of the container's memory, floored and capped.
//
// Returns fallback when there is no limit to take a share of — deliberately a
// modest absolute number rather than a share of the host, because a service that
// cannot see a limit is usually one of several on a shared machine.
func Budget(share float64, fallback, min, max int64) int64 {
	limit := MemoryLimit()
	if limit <= 0 {
		return clamp(fallback, min, max)
	}
	return clamp(int64(float64(limit)*share), min, max)
}

// CPUs is how many cores the cgroup allows, rounded up, or NumCPU when unlimited.
//
// runtime.NumCPU reports the machine's cores, not the container's quota, so a
// library sizing a thread pool from it oversubscribes every capped container.
func CPUs() int {
	b, err := os.ReadFile("/sys/fs/cgroup/cpu.max")
	if err != nil {
		return runtime.NumCPU()
	}
	f := strings.Fields(strings.TrimSpace(string(b)))
	if len(f) != 2 || f[0] == "max" {
		return runtime.NumCPU()
	}
	quota, err1 := strconv.ParseInt(f[0], 10, 64)
	period, err2 := strconv.ParseInt(f[1], 10, 64)
	if err1 != nil || err2 != nil || period <= 0 || quota <= 0 {
		return runtime.NumCPU()
	}
	n := int((quota + period - 1) / period) // round up: 1.5 cores is 2 threads
	if n < 1 {
		return 1
	}
	if n > runtime.NumCPU() {
		return runtime.NumCPU()
	}
	return n
}

func clamp(v, min, max int64) int64 {
	if v < min {
		return min
	}
	if max > 0 && v > max {
		return max
	}
	return v
}

func readBytes(path string) (int64, bool) {
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
