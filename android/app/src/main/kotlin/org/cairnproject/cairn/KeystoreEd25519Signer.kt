// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors
package org.cairnproject.cairn

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.File
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import uniffi.cairn_uniffi.AttestationCertificate
import uniffi.cairn_uniffi.CairnFfiException
import uniffi.cairn_uniffi.HardwareKeySigner
import uniffi.cairn_uniffi.HardwarePublicKey
import uniffi.cairn_uniffi.KeyGenSpec

/**
 * The v1 hardware-backed device key (D0020 §3.4 / D0028) — replaces the demo
 * software key as the [HardwareKeySigner] the Rust core calls to sign each
 * message envelope's `COSE_Sign1`. The private key is generated in the
 * AndroidKeyStore and **never leaves hardware**; only signature + public bytes
 * cross the FFI.
 *
 * **Ed25519, not P-256.** The original §3.4 sketch used `SHA256withECDSA` /
 * `secp256r1`, whose AndroidKeyStore output is ASN.1-DER (X.509 SPKI key +
 * DER-wrapped signature) — incompatible with `cairn-envelope`'s ed25519-dalek
 * verifier, which needs a RAW 32-byte public key + RAW 64-byte signature. The
 * earlier on-device "wire-incompatible" finding was exactly this mismatch. The
 * fix is to keep the protocol on Ed25519 (EdDSA), whose signatures are raw by
 * construction and whose public key is the trailing 32 bytes of the SPKI.
 *
 * **TEE, not StrongBox.** Per D0020 §3.5 the per-MESSAGE device key lives in the
 * TEE — StrongBox EC ops are seconds-scale, and the Pixel's Titan-M2 rejects
 * Ed25519 outright (`Unsupported StrongBox EC: ed25519`, confirmed on-device).
 * StrongBox is reserved for the operational-identity key that signs capability
 * tokens periodically (a separate, future surface). A TEE key is still
 * hardware-backed + `NeverExport`.
 *
 * If the platform cannot produce a raw-Ed25519 hardware key at all,
 * [generateOrLoad] returns `null` and the caller falls back to the software demo
 * identity — the app must never brick on a key-provisioning gap.
 */
class KeystoreEd25519Signer private constructor(
    /** Raw 32-byte Ed25519 public key (envelope device/operational pubkey). */
    val publicKeyRaw: ByteArray,
    /** "StrongBox" / "TEE" / "software" — the element the key actually landed in. */
    val securityLevel: String,
    /**
     * The 32-byte attestation challenge embedded in the key's attestation
     * certificate at generation (D0033 §1) — passed to the Rust verifier so it
     * can confirm the leaf cert binds OUR challenge. Empty if the key predates
     * attestation (a defensive fallback; the v2 alias always has one).
     */
    val attestationChallenge: ByteArray,
) : HardwareKeySigner {

    override fun sign(keyAlias: String, payload: ByteArray): ByteArray {
        // getKey, NOT getEntry: constructing a KeyStore.PrivateKeyEntry
        // cross-checks the private-key algorithm against the self-signed cert's
        // public-key algorithm, which MISMATCHES for an AndroidKeyStore Ed25519
        // key ("private key algorithm does not match algorithm of public key in
        // end entity certificate", confirmed on-device). getKey returns the
        // opaque PrivateKey handle directly — the key bytes never leave the TEE.
        val priv = loadKeyStore().getKey(keyAlias, null) as? java.security.PrivateKey
            ?: throw CairnFfiException.SidecarFailure()
        return try {
            Signature.getInstance(ED25519).run {
                initSign(priv) // signs in the TEE; the key never crosses
                update(payload)
                sign() // Ed25519: RAW 64-byte (R||S), no DER, no external digest
            }
        } catch (e: Exception) {
            Log.w(TAG, "hardware sign failed (${e.javaClass.simpleName}: ${e.message})")
            throw CairnFfiException.SidecarFailure()
        }
    }

    override fun generateKey(keyAlias: String, spec: KeyGenSpec): HardwarePublicKey {
        // The device key is provisioned by generateOrLoad; this callback is the
        // Rust-driven path (e.g. attestation round-trip). Return the SPKI DER.
        val cert = loadKeyStore().getCertificate(keyAlias)
            ?: throw CairnFfiException.SidecarFailure()
        return HardwarePublicKey(cert.publicKey.encoded)
    }

    override fun attestationChain(keyAlias: String): List<AttestationCertificate> {
        val chain = loadKeyStore().getCertificateChain(keyAlias)
            ?: throw CairnFfiException.SidecarFailure()
        return chain.map { AttestationCertificate(it.encoded) }
    }

    companion object {
        private const val TAG = "CairnFfi"

        /**
         * The AndroidKeyStore alias for the persistent device key. The `-v2`
         * suffix forces a fresh ATTESTED keygen (D0033 §5 migration): the v1
         * key was generated without `setAttestationChallenge`, so no real
         * attestation chain exists for it — a new alias regenerates the key WITH
         * a challenge (and thus a new operational identity; fresh installs only).
         */
        const val DEVICE_KEY_ALIAS = "cairn-device-key-ed25519-v2"

        /** File (under filesDir) holding the device key's attestation challenge. */
        private const val CHALLENGE_FILE = "device-attest-challenge-v2.bin"

        /** Attestation challenge length (D0033 §1) — a 32-byte freshness nonce. */
        private const val CHALLENGE_LEN = 32

        /** JCA signature algorithm for pure Ed25519 (no external digest). */
        private const val ED25519 = "Ed25519"

        /** AndroidKeyStore curve name for Ed25519 (API 33+). */
        private const val ED25519_CURVE = "ed25519"

        private fun loadKeyStore(): KeyStore =
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

        /**
         * Generate-or-load the persistent hardware Ed25519 device key. Returns
         * `null` (caller falls back to the software demo identity) if the
         * platform can't provide a raw-Ed25519 hardware key.
         *
         * @param requireAuth gate each signature on biometric/device-credential
         *   (v1 will set this; the demo leaves it false so signing is silent).
         */
        fun generateOrLoad(
            filesDir: File,
            alias: String = DEVICE_KEY_ALIAS,
            requireAuth: Boolean = false,
        ): KeystoreEd25519Signer? {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                Log.w(TAG, "AndroidKeyStore Ed25519 needs API 33+, have ${Build.VERSION.SDK_INT}")
                return null
            }
            return try {
                val ks = loadKeyStore()
                val challengeFile = File(filesDir, CHALLENGE_FILE)
                // Self-heal: an existing key generated under earlier params (e.g.
                // before DIGEST_NONE was authorized) cannot sign — drop + regen
                // (and drop its now-stale challenge so a fresh one is minted).
                if (ks.containsAlias(alias) && !canSign(ks, alias)) {
                    Log.i(TAG, "existing device key cannot sign (stale params) — regenerating")
                    ks.deleteEntry(alias)
                    challengeFile.delete()
                }
                val challenge: ByteArray
                if (ks.containsAlias(alias)) {
                    // Key exists → its attestation challenge was persisted at
                    // generation. Empty if the file was removed out-of-band (the
                    // verifier then can't bind the challenge but still checks the
                    // chain + KeyMint properties).
                    challenge = runCatching { challengeFile.readBytes() }.getOrDefault(ByteArray(0))
                } else {
                    // Fresh key → mint + persist the attestation challenge, then
                    // generate the key bound to it (D0033 §1).
                    challenge = ByteArray(CHALLENGE_LEN).also { SecureRandom().nextBytes(it) }
                    runCatching { challengeFile.writeBytes(challenge) }
                    generateKeyPair(alias, requireAuth, challenge)
                }
                val pub = ks.getCertificate(alias).publicKey
                val raw = rawEd25519PublicKey(pub.encoded)
                val level = securityLevelOf(ks, alias)
                Log.i(
                    TAG,
                    "hardware device key ready: alias=$alias level=$level pub=${raw.size}B challenge=${challenge.size}B",
                )
                KeystoreEd25519Signer(raw, level, challenge)
            } catch (e: Exception) {
                Log.w(
                    TAG,
                    "hardware Ed25519 key unavailable (${e.javaClass.simpleName}: ${e.message}) — using software demo key",
                    e,
                )
                null
            }
        }

        /** True if the alias's key can produce an Ed25519 signature right now. */
        private fun canSign(ks: KeyStore, alias: String): Boolean =
            try {
                val priv = ks.getKey(alias, null) as java.security.PrivateKey
                Signature.getInstance(ED25519).apply {
                    initSign(priv)
                    update(byteArrayOf(0x01))
                    sign()
                }
                true
            } catch (e: Exception) {
                false
            }

        private fun generateKeyPair(alias: String, requireAuth: Boolean, challenge: ByteArray) {
            // The per-MESSAGE device key lives in the TEE, NOT StrongBox (D0020
            // §3.5): StrongBox EC ops are seconds-scale, and many StrongBox impls
            // (e.g. the Pixel's Titan-M2) reject Ed25519 outright ("Unsupported
            // StrongBox EC: ed25519"). StrongBox is reserved for the
            // operational-identity key that signs capability tokens periodically.
            // Omitting setIsStrongBoxBacked yields a TEE-hardware-backed key.
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec(ED25519_CURVE))
                // Ed25519 is pure EdDSA — it signs with NO external digest. The
                // key must be AUTHORIZED for DIGEST_NONE or KeyMint rejects the
                // sign op ("Digest 0 not authorized by key" → INCOMPATIBLE_DIGEST,
                // confirmed on-device).
                .setDigests(KeyProperties.DIGEST_NONE)
                .setUserAuthenticationRequired(requireAuth)
                // Attestation (D0033 §1): with a challenge, KeyMint emits the leaf
                // attestation extension (OID 1.3.6.1.4.1.11129.2.1.17) + the cert
                // chain to Google's Hardware Attestation Root, so the key's
                // hardware origin + non-exportability can be VERIFIED Rust-side
                // (vs the self-reported KeyInfo.securityLevel).
                .setAttestationChallenge(challenge)
                .build()
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                .apply { initialize(spec) }
                .generateKeyPair()
            Log.i(TAG, "generated TEE-backed Ed25519 device key WITH attestation (alias=$alias)")
        }

        /**
         * The raw 32-byte Ed25519 key from a SubjectPublicKeyInfo. Ed25519 SPKI
         * is a fixed 12-byte prefix + the 32-byte key, so the trailing 32 bytes
         * ARE the raw key the verifier needs.
         */
        private fun rawEd25519PublicKey(spki: ByteArray): ByteArray {
            require(spki.size >= 32) { "SPKI too short (${spki.size}B) for Ed25519" }
            return spki.copyOfRange(spki.size - 32, spki.size)
        }

        private fun securityLevelOf(ks: KeyStore, alias: String): String {
            val priv = try {
                ks.getKey(alias, null) as java.security.PrivateKey
            } catch (e: Exception) {
                return "unknown"
            }
            // KeyInfo introspection of an AndroidKeyStore EdEC key is flaky (the
            // KeyFactory algorithm name varies); try the reported algorithm then
            // common fallbacks. If none yield KeyInfo, the key is still
            // hardware-backed by construction (generated non-StrongBox in the
            // AndroidKeyStore on a TEE device) — report "hardware" honestly. The
            // cryptographic proof of the element is the attestation chain,
            // verified Rust-side per D0020 §3.8 (a follow-up).
            val info = sequenceOf(priv.algorithm, "EC", "XDH", "Ed25519")
                .distinct()
                .firstNotNullOfOrNull { alg ->
                    runCatching {
                        KeyFactory.getInstance(alg, "AndroidKeyStore")
                            .getKeySpec(priv, KeyInfo::class.java)
                    }.getOrNull()
                } ?: return "hardware(${priv.algorithm})"
            return when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
                else -> "level(${info.securityLevel})"
            }
        }
    }
}
