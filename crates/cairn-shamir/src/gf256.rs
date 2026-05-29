// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Constant-time arithmetic in `GF(2⁸)` (the Rijndael field).
//!
//! All operations operate on `u8` and run in constant time relative to
//! their inputs — no data-dependent branches, no table lookups indexed by
//! secret values. The primitives here are the foundation of the
//! byte-level Shamir split / reconstruct algorithms in [`crate::share`].
//!
//! ## Field choice
//!
//! `GF(2⁸)` with the Rijndael reduction polynomial
//! `x⁸ + x⁴ + x³ + x + 1 = 0x11B`. This is the same field used by AES,
//! making the implementation interoperable with well-studied test
//! vectors and broadly understood. The reduction byte (the low 8 bits of
//! the polynomial, `0x1B`) is the load-bearing constant in [`mul`].
//!
//! ## Constant-time discipline
//!
//! - [`mul`]: shift-and-conditional-XOR with bitmask arithmetic instead
//!   of a conditional branch. The loop runs exactly 8 iterations
//!   regardless of input.
//! - [`inv`]: Fermat's little theorem `a⁻¹ = a²⁵⁴` via square-and-
//!   multiply with a fixed schedule of 14 multiplications. The loop
//!   structure is identical for any non-zero input.
//! - [`add`] / [`sub`]: both are `XOR` in characteristic-2 fields, so
//!   trivially constant-time.
//!
//! ## What this module does NOT do
//!
//! - No log/exp tables. Table-based multiplication would be faster but
//!   timing-side-channel-vulnerable on architectures with shared CPU
//!   caches.
//! - No SIMD. PCLMULQDQ-based multiplication would also be faster but
//!   requires runtime feature detection, which complicates the
//!   constant-time analysis. The bit-serial multiplication runs in
//!   single-digit nanoseconds per byte on modern CPUs — well below
//!   the timing precision Cairn's threat model needs.

/// Addition in `GF(2⁸)` (= XOR).
#[must_use]
pub const fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Subtraction in `GF(2⁸)` (= XOR — same operation as addition in
/// characteristic-2 fields).
#[must_use]
pub const fn sub(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Multiplication in `GF(2⁸)` using the Rijndael reduction polynomial
/// `0x11B`.
///
/// Constant-time by construction: 8-iteration loop with bitmask
/// arithmetic rather than data-dependent branches. The
/// `(b & 1).wrapping_neg()` idiom produces `0xFF` when the LSB of `b`
/// is set and `0x00` otherwise — the same number of cycles regardless
/// of input.
#[must_use]
pub const fn mul(a: u8, b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut a = a;
    let mut b = b;
    // `i.wrapping_add(1)` avoids the `arithmetic_side_effects` lint
    // without changing behavior: `i` is bounded `[0, 7]` by the loop
    // guard, so `i + 1` never overflows. The wrapping form makes the
    // proof local at the call site rather than at a global allow.
    let mut i: u8 = 0;
    while i < 8 {
        // If the LSB of `b` is set, mask is `0xFF`; otherwise `0x00`.
        let mask_b = (b & 1).wrapping_neg();
        result ^= a & mask_b;
        // If the high bit of `a` was set, XOR with the reduction byte
        // after the shift.
        let mask_high = ((a >> 7) & 1).wrapping_neg();
        a = (a << 1) ^ (mask_high & 0x1B);
        b >>= 1;
        i = i.wrapping_add(1);
    }
    result
}

/// Multiplicative inverse in `GF(2⁸)`.
///
/// Computes `a⁻¹ = a²⁵⁴` via Fermat's little theorem (the multiplicative
/// group of `GF(2⁸)` has order 255, so for any non-zero `a`, `a²⁵⁵ = 1`
/// and `a²⁵⁴ = a⁻¹`).
///
/// The exponent `254` decomposes as `0b1111_1110` — every bit except the
/// LSB. The square-and-multiply schedule runs the same 7 squarings + 6
/// multiplications for any non-zero input, making the operation
/// constant-time.
///
/// **Caller contract**: this function returns `0` when called with
/// `a = 0`. The Shamir reconstruction caller ([`crate::share`]) MUST
/// reject `0` inputs *before* calling this function, since `gf256::inv(0)`
/// is mathematically undefined; the constant-time loop produces `0` only
/// as a degenerate fall-through, NOT as a meaningful inverse.
#[must_use]
pub const fn inv(a: u8) -> u8 {
    // Compute a^254 = a^(128+64+32+16+8+4+2)
    //               = a^128 * a^64 * a^32 * a^16 * a^8 * a^4 * a^2
    let a2 = mul(a, a); // a^2
    let a4 = mul(a2, a2); // a^4
    let a8 = mul(a4, a4); // a^8
    let a16 = mul(a8, a8); // a^16
    let a32 = mul(a16, a16); // a^32
    let a64 = mul(a32, a32); // a^64
    let a128 = mul(a64, a64); // a^128
    let p1 = mul(a128, a64); // a^192
    let p2 = mul(p1, a32); // a^224
    let p3 = mul(p2, a16); // a^240
    let p4 = mul(p3, a8); // a^248
    let p5 = mul(p4, a4); // a^252
    mul(p5, a2) // a^254
}

/// Evaluate a polynomial with `GF(2⁸)` coefficients at point `x` using
/// Horner's method.
///
/// `coeffs[0]` is the constant term, `coeffs[1]` is the `x¹` coefficient,
/// etc. Runs in linear time in the polynomial degree with no
/// data-dependent branches.
#[must_use]
pub fn poly_eval(coeffs: &[u8], x: u8) -> u8 {
    let mut result: u8 = 0;
    for &c in coeffs.iter().rev() {
        result = add(mul(result, x), c);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_is_xor() {
        // For any (a, b), add(a, b) == a ^ b.
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                assert_eq!(add(a, b), a ^ b);
            }
        }
    }

    #[test]
    fn sub_is_xor() {
        // Same as add() in characteristic-2.
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                assert_eq!(sub(a, b), a ^ b);
            }
        }
    }

    #[test]
    fn mul_zero_absorbs() {
        for a in 0u8..=255 {
            assert_eq!(mul(0, a), 0);
            assert_eq!(mul(a, 0), 0);
        }
    }

    #[test]
    fn mul_one_is_identity() {
        for a in 0u8..=255 {
            assert_eq!(mul(1, a), a);
            assert_eq!(mul(a, 1), a);
        }
    }

    #[test]
    fn mul_is_commutative() {
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                assert_eq!(mul(a, b), mul(b, a));
            }
        }
    }

    #[test]
    fn mul_known_vectors() {
        // Standard AES `GF(2⁸)` multiplication test vectors.
        // 0x53 * 0xCA = 0x01 per FIPS 197 §4.2 example.
        assert_eq!(mul(0x53, 0xCA), 0x01);
        // 0x57 * 0x83 = 0xC1 per FIPS 197 §4.2.1 example.
        assert_eq!(mul(0x57, 0x83), 0xC1);
        // 0x57 * 0x13 = 0xFE per FIPS 197 §4.2.1 example.
        assert_eq!(mul(0x57, 0x13), 0xFE);
    }

    #[test]
    fn inv_round_trip_nonzero() {
        // For every non-zero `a`, a * inv(a) = 1.
        for a in 1u8..=255 {
            let inv_a = inv(a);
            assert_eq!(
                mul(a, inv_a),
                1,
                "a={a:#x}, inv(a)={inv_a:#x}, mul={:#x}",
                mul(a, inv_a)
            );
        }
    }

    #[test]
    fn inv_one_is_one() {
        assert_eq!(inv(1), 1);
    }

    #[test]
    fn inv_zero_returns_zero_degenerate() {
        // Document the degenerate fallthrough: inv(0) = 0 (not a true
        // mathematical inverse). Callers must reject 0 before calling.
        assert_eq!(inv(0), 0);
    }

    #[test]
    fn poly_eval_at_zero_is_constant_term() {
        // p(0) = c_0 regardless of higher-order coefficients.
        for c0 in 0u8..=10 {
            let coeffs = vec![c0, 5, 7, 11];
            assert_eq!(poly_eval(&coeffs, 0), c0);
        }
    }

    #[test]
    fn poly_eval_constant_polynomial() {
        // p(x) = c, evaluates to c at every x.
        let coeffs = vec![42u8];
        for x in 0u8..=255 {
            assert_eq!(poly_eval(&coeffs, x), 42);
        }
    }

    #[test]
    fn poly_eval_linear_polynomial() {
        // p(x) = 3 + 7x, p(1) = 3 ^ 7 = 4.
        let coeffs = vec![3, 7];
        // GF arithmetic: poly_eval(&[3, 7], 1) = 3 + 7*1 = 3 ^ 7 = 4.
        assert_eq!(poly_eval(&coeffs, 1), 3 ^ 7);
        // p(2) = 3 + 7*2 = 3 ^ mul(7, 2).
        assert_eq!(poly_eval(&coeffs, 2), 3 ^ mul(7, 2));
    }

    #[test]
    fn poly_eval_empty_is_zero() {
        // The empty polynomial is the zero polynomial.
        assert_eq!(poly_eval(&[], 0), 0);
        assert_eq!(poly_eval(&[], 42), 0);
    }
}
