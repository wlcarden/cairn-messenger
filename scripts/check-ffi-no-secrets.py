#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cairn maintainers and contributors
"""CI guard: no NeverExport secret-carrier type may be a `uniffi::Record` field.

D0020 §3.6/§3.7 + D0027 §4: secret-bearing types MUST NOT cross the UniFFI
boundary. Stable Rust cannot express a negative trait impl, so the
`assert_exportable::<T>()` calls in `never_export_gate.rs` are a centralized
ALLOW-LIST (a review checkpoint), not a hard compile gate — a listed carrier
that *became* secret-bearing would still compile. This source scan is the
executable half: it fails the build if a known secret-carrier type name appears
as a field of any `#[derive(uniffi::Record)]` struct in `cairn-uniffi`, which is
the precise regression (e.g. adding the master seed / a `Zeroizing` /
`SecretBox` field to `RecoveryCardRecord` or `ShareRecord`).

Scope note: this checks Record *fields*. Exported functions in `cairn-uniffi`
take/return only Records + public scalars (`Vec<u8>`, `String`, `u64`, `bool`);
their bodies legitimately use secret types (e.g. `recovery.rs` reconstructs in
`Zeroizing`), so a whole-file grep would false-positive — the Record-field scan
targets the field-lowering position without that noise.
"""
from __future__ import annotations

import pathlib
import re
import sys

# Concrete secret-bearing carrier type names that must never be a lowered field.
DENY = [
    "SecretBox",
    "Zeroizing",
    "SigningKey",
    "StaticSecret",
    "EphemeralSecret",
    "SecretKey",
    "NeverExport",
    "Seed",
]
DENY_RE = re.compile(r"\b(" + "|".join(DENY) + r")\b")

SRC = pathlib.Path("crates/cairn-uniffi/src")


def record_field_violations(path: pathlib.Path) -> list[tuple[int, str, str]]:
    """Return (line_no, line_text, matched_token) for denylisted types appearing
    as a field inside any `#[derive(uniffi::Record)]` struct in `path`."""
    lines = path.read_text(encoding="utf-8").splitlines()
    out: list[tuple[int, str, str]] = []
    i, n = 0, len(lines)
    while i < n:
        code = lines[i].split("//", 1)[0]
        # A Record derive (direct or via cfg_attr) — both contain `derive` AND
        # `uniffi::Record` on the same attribute line. Comments are stripped above.
        if "uniffi::Record" in code and "derive" in code:
            # Advance to the struct's opening brace.
            j = i
            while j < n and "{" not in lines[j]:
                j += 1
            # Walk the struct body, tracking brace depth, until it closes.
            depth = 0
            k = j
            while k < n:
                depth += lines[k].count("{") - lines[k].count("}")
                if k > j:  # inside the body, past the opening-brace line
                    field = lines[k].split("//", 1)[0]
                    m = DENY_RE.search(field)
                    if m:
                        out.append((k + 1, lines[k].strip(), m.group(0)))
                if depth <= 0 and "{" in "".join(lines[j : k + 1]):
                    break
                k += 1
            i = k + 1
            continue
        i += 1
    return out


def main() -> int:
    if not SRC.is_dir():
        print(f"::error::{SRC} not found (run from the repo root)")
        return 2
    violations: list[tuple[pathlib.Path, int, str, str]] = []
    for path in sorted(SRC.rglob("*.rs")):
        for ln, text, tok in record_field_violations(path):
            violations.append((path, ln, text, tok))
    if violations:
        print(
            "::error::NeverExport secret-carrier type as a uniffi::Record field "
            "(D0020 §3.7 / D0027 §4 — secrets must not cross the FFI boundary):"
        )
        for path, ln, text, tok in violations:
            print(f"  {path}:{ln}: `{tok}` in `{text}`")
        return 1
    print("OK: no NeverExport secret-carrier type appears as a uniffi::Record field.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
