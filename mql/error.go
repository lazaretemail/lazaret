// SPDX-License-Identifier: AGPL-3.0-only

package mql

import (
	"fmt"
	"sort"
	"strings"
)

// Error is a diagnostic tied to a position in the source.
type Error struct {
	Pos Pos
	Msg string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Pos, e.Msg) }

// ErrorList collects diagnostics. Compilation is best-effort: reporting every problem in a
// rule at once beats making the author fix them one round-trip at a time.
type ErrorList []*Error

func (l ErrorList) Error() string {
	switch len(l) {
	case 0:
		return "no errors"
	case 1:
		return l[0].Error()
	}
	var b strings.Builder
	for i, e := range l {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(e.Error())
	}
	return b.String()
}

// Err returns the list as an error, or nil when it is empty, so callers can write
// `return errs.Err()` without a length check.
func (l ErrorList) Err() error {
	if len(l) == 0 {
		return nil
	}
	return l
}

// Sorted returns the diagnostics in source order. Recovery can append out of order, and
// output that jumps around the file is hard to act on.
func (l ErrorList) Sorted() ErrorList {
	out := make(ErrorList, len(l))
	copy(out, l)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Pos.Offset < out[j].Pos.Offset })
	return out
}

// Render formats the diagnostics against their source, underlining each with a caret.
//
//	3:22: no such field "emial" on SenderMailbox
//	  |
//	3 |     sender.emial == "x"
//	  |            ^
//
// Columns count runes, so the caret lands correctly in rules that match on homoglyphs or
// emoji — which, in an email security product, is most of the interesting ones.
func (l ErrorList) Render(src string) string {
	lines := strings.Split(src, "\n")
	var b strings.Builder
	for i, e := range l.Sorted() {
		if i > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "%s\n", e.Error())
		if e.Pos.Line < 1 || e.Pos.Line > len(lines) {
			continue
		}
		text := strings.ReplaceAll(lines[e.Pos.Line-1], "\t", " ")
		gutter := fmt.Sprintf("%d", e.Pos.Line)
		pad := strings.Repeat(" ", len(gutter))
		fmt.Fprintf(&b, "%s |\n", pad)
		fmt.Fprintf(&b, "%s | %s\n", gutter, text)
		fmt.Fprintf(&b, "%s | %s^\n", pad, strings.Repeat(" ", max(e.Pos.Column-1, 0)))
	}
	return b.String()
}
