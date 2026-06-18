// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

// Package gocose cross-validates Cairn's COSE_Sign1 envelope test vectors
// against veraison/go-cose, the independent Go COSE implementation named as
// the D0018 §2.4 / §2.5 interop oracle. It reads the pinned JSON vectors in
// crates/cairn-envelope/tests/vectors/ and asserts go-cose decodes each
// envelope and verifies its Ed25519 signature under the documented key and
// external AAD. This is the Go side the vectors README (lines 58-63) and
// cose_sign1.rs's interop_tests module defer "until the Go toolchain lands".
package gocose

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/veraison/go-cose"
)

// vector mirrors the subset of the vector JSON schema (tests/vectors/README.md)
// the cross-check needs. signing_key_seed_hex is the Ed25519 seed of the key
// that signed the envelope; deriving the public key from it sidesteps the
// per-vector *_verifying_key_hex field-name variation.
type vector struct {
	Name           string `json:"name"`
	SigningKeySeed string `json:"signing_key_seed_hex"`
	ExternalAADHex string `json:"external_aad_hex"`
	PayloadHex     string `json:"payload_cbor_hex"`
	EnvelopeHex    string `json:"envelope_cbor_hex"`
}

func mustHex(t *testing.T, label, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%s: bad hex: %v", label, err)
	}
	return b
}

// TestCrossValidateVectors runs every pinned vector through go-cose.
func TestCrossValidateVectors(t *testing.T) {
	dir := filepath.Join("..", "..", "tests", "vectors")
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatalf("glob vectors: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("no vectors found in %s (run from the module dir)", dir)
	}

	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var v vector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		t.Run(v.Name, func(t *testing.T) {
			seed := mustHex(t, "signing_key_seed_hex", v.SigningKeySeed)
			if len(seed) != ed25519.SeedSize {
				t.Fatalf("seed length %d, want %d", len(seed), ed25519.SeedSize)
			}
			pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
			aad := mustHex(t, "external_aad_hex", v.ExternalAADHex)
			env := mustHex(t, "envelope_cbor_hex", v.EnvelopeHex)

			// 1. go-cose decodes the untagged COSE_Sign1 4-tuple.
			var msg cose.UntaggedSign1Message
			if err := msg.UnmarshalCBOR(env); err != nil {
				t.Fatalf("go-cose could not decode Cairn envelope: %v", err)
			}

			// 2. The decoded payload matches the pinned payload bytes.
			wantPayload := mustHex(t, "payload_cbor_hex", v.PayloadHex)
			if !bytes.Equal(msg.Payload, wantPayload) {
				t.Fatalf("payload mismatch:\n have %x\n want %x", msg.Payload, wantPayload)
			}

			// 3. go-cose verifies the Ed25519 signature under the derived
			//    key + external AAD. A divergent Sig_structure would fail
			//    here, so this transitively confirms the §4.4 construction.
			verifier, err := cose.NewVerifier(cose.AlgorithmEd25519, pub)
			if err != nil {
				t.Fatalf("new verifier: %v", err)
			}
			sign1 := cose.Sign1Message(msg)
			if err := sign1.Verify(aad, verifier); err != nil {
				t.Fatalf("go-cose verify FAILED for Cairn-emitted envelope: %v", err)
			}

			// 4. A single-byte tamper of the signature must break
			//    verification (guards against an accept-anything bug in the
			//    cross-check itself).
			tampered := bytes.Clone(env)
			tampered[len(tampered)-1] ^= 0x01
			var tmsg cose.UntaggedSign1Message
			if err := tmsg.UnmarshalCBOR(tampered); err == nil {
				ts := cose.Sign1Message(tmsg)
				if err := ts.Verify(aad, verifier); err == nil {
					t.Fatal("tampered envelope unexpectedly verified")
				}
			}
		})
	}
}
