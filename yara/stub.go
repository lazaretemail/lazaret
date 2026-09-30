// SPDX-License-Identifier: AGPL-3.0-only

//go:build !yara

package yara

// This is the default build: no cgo, no native library, no scanning.
//
// The alternative would be to make YARA-X a hard dependency, which would mean anyone
// wanting to lint a rule or parse a message needed a Rust toolchain and a compiled C API
// on their machine. That is too high a price for a capability most callers do not use.

func available() bool { return false }

func compile(sources map[string]string) (Scanner, error) { return nil, ErrUnsupported }
