// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

// Standalone Go module for the D0018 §2.4 cross-implementation interop
// gate. Not part of the Rust workspace; run with `go test ./...` from this
// directory (or via the go-cose-interop CI job).
module cairn-cose-interop

go 1.26

require github.com/veraison/go-cose v1.3.0

require (
	github.com/fxamacker/cbor/v2 v2.5.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
)
