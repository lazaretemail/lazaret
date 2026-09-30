// SPDX-License-Identifier: AGPL-3.0-only

package mdm

// types.gen.go and enrichment.gen.go are derived from the vendored upstream schemas:
// the Message Data Model, and the file-explosion and link-analysis outputs that Sublime
// publishes inside their API reference pages. Regenerate with `go generate ./mdm` after
// updating either document; CI fails if the generated files and the schemas disagree.
//
// The enrichment outputs that have no published schema at all are hand-written in
// enrichment.go, reconstructed from how the public rule corpus uses them.
//
//go:generate go run ./gen -in mdm.openapi.json -out types.gen.go
//go:generate go run ./gen -in enrichment.openapi.json -out enrichment.gen.go
