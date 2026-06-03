// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.util.Log
import java.io.File
import java.security.SecureRandom
import uniffi.cairn_uniffi.AttestationCertificate
import uniffi.cairn_uniffi.CairnFfiException
import uniffi.cairn_uniffi.DemoEd25519Signer
import uniffi.cairn_uniffi.HardwareKeySigner
import uniffi.cairn_uniffi.HardwarePublicKey
import uniffi.cairn_uniffi.KeyGenSpec
import uniffi.cairn_uniffi.SidecarEndpointConfig
import uniffi.cairn_uniffi.SimplexAdapterHandle
import uniffi.cairn_uniffi.StorageHandle
import uniffi.cairn_uniffi.StrongBoxKeyMaterial

/**
 * DEMO identity + session bootstrap for the chat UI.
 *
 * **NOT the v1 hardened path.** The real device key signs in StrongBox via the
 * `HardwareKeySigner` callback (D0020 §3.4 / D0028 — pending), where the key
 * never crosses the FFI. Here a SOFTWARE Ed25519 key stands in so the UI + the
 * bundled-Tor transport can be exercised end-to-end. Signing routes through
 * [DemoEd25519Signer] — the SAME `cairn-crypto` ed25519-dalek the envelope
 * verifier uses — so the COSE_Sign1 signature + the operational pubkey are
 * byte-compatible with verification. (AndroidKeyStore's Ed25519 is NOT: its
 * X.509/DER key + signature encodings fail the raw-32-byte `VerifyingKey` and
 * raw-64-byte signature checks — the on-device two-party finding, D0026 §12.)
 * The one key serves as BOTH the device key (it signs the envelope) and the
 * operational key (the envelope sender) — valid for the 1:1 demo, where the two
 * peers exchange pubkeys alongside the invitation.
 */

/**
 * Label for the device key the FFI signer passes through to the
 * [HardwareKeySigner]; the demo software signer ignores it (the v1 StrongBox
 * path keys on it, D0028).
 */
const val DEMO_DEVICE_KEY_ALIAS = "cairn-demo-op-key"

/** Ed25519 seed length — matches `cairn_crypto::ed25519::SEED_LEN`. */
private const val ED25519_SEED_LEN = 32

/**
 * An ephemeral SOFTWARE Ed25519 demo identity. A fresh 32-byte seed is minted
 * per launch ([SecureRandom]) and handed to [DemoEd25519Signer] (Rust
 * `cairn-crypto`); the raw 32-byte pubkey + raw 64-byte signatures it produces
 * are exactly what `cairn-envelope` verifies. The v1 hardening replaces this
 * with a StrongBox key + attestation (D0020 §3.4 / D0028).
 */
class CairnIdentity private constructor(
    private val signer: DemoEd25519Signer,
    /** Raw 32-byte Ed25519 public key — the envelope operational + device pubkey. */
    val publicKeyRaw: ByteArray,
) {
    /** Ed25519 signature (64 bytes) over [payload] via the demo software key. */
    fun sign(payload: ByteArray): ByteArray = signer.sign(payload)

    companion object {
        /** Mint a fresh ephemeral demo identity (a new software key per launch). */
        fun generate(): CairnIdentity {
            val seed = ByteArray(ED25519_SEED_LEN).also { SecureRandom().nextBytes(it) }
            val signer = DemoEd25519Signer.fromSeed(seed)
            return CairnIdentity(signer, signer.publicKey())
        }
    }
}

/**
 * Software [HardwareKeySigner] over the demo Ed25519 identity. Only [sign] is
 * real (the messaging send path uses it); StrongBox key-gen + attestation are
 * the v1 hardening (D0028) and are not exercised by the demo.
 */
class DemoSigner(private val identity: CairnIdentity) : HardwareKeySigner {
    override fun sign(keyAlias: String, payload: ByteArray): ByteArray =
        identity.sign(payload)

    override fun generateKey(keyAlias: String, spec: KeyGenSpec): HardwarePublicKey =
        throw CairnFfiException.MalformedData() // demo: StrongBox key-gen is D0028

    override fun attestationChain(keyAlias: String): List<AttestationCertificate> =
        throw CairnFfiException.MalformedData() // demo: no hardware attestation
}

/**
 * Fixed [StrongBoxKeyMaterial] for the demo storage KEK (32 bytes). The real
 * material is StrongBox-attested + device-bound (D0022 §2.2); here it is a
 * constant so the encrypted store opens deterministically for the demo.
 */
class DemoKeyMaterial : StrongBoxKeyMaterial {
    override fun strongboxMaterial(): ByteArray = ByteArray(32) { 0x2A }
    override fun isUnlocked(): Boolean = true
}

/** The bundled-Tor SOCKS endpoint the in-process libsimplex routes through. */
private const val BUNDLED_TOR_SOCKS = "127.0.0.1:9050"

/**
 * The constructed messaging session: the demo identity + the opened encrypted
 * store + the [SimplexAdapterHandle] over the per-target transport (the Android
 * in-process FFI transport, routed through the bundled Tor's SOCKS proxy).
 */
class CairnSession private constructor(
    /** Raw 32-byte Ed25519 device/operational public key (the envelope sender id). */
    val publicKeyRaw: ByteArray,
    val handle: SimplexAdapterHandle,
) {
    companion object {
        private const val TAG = "CairnFfi"

        /**
         * Bootstrap the session under [filesDir]. Uses the **hardware-backed
         * Ed25519 device key** ([KeystoreEd25519Signer]) when the platform can
         * provide one, falling back to the software demo identity otherwise so
         * the app never bricks on a key-provisioning gap.
         */
        fun bootstrap(filesDir: File): CairnSession {
            val storage = StorageHandle.open(
                "${filesDir.absolutePath}/store.db",
                // Demo passphrase — the real one is user-entered at unlock.
                "cairn-demo-passphrase".toByteArray(),
                DemoKeyMaterial(),
            )

            // Prefer the hardware-backed Ed25519 device key (D0020 §3.4 / D0028);
            // its private key never leaves the TEE/StrongBox — the signer is the
            // HardwareKeySigner callback the Rust core invokes to sign each
            // envelope. Fall back to the software demo identity if unavailable.
            val signer: HardwareKeySigner
            val publicKeyRaw: ByteArray
            val keyAlias: String
            val hardware = KeystoreEd25519Signer.generateOrLoad()
            if (hardware != null) {
                signer = hardware
                publicKeyRaw = hardware.publicKeyRaw
                keyAlias = KeystoreEd25519Signer.DEVICE_KEY_ALIAS
                Log.i(TAG, "CairnSession: HARDWARE device key (${hardware.securityLevel})")
            } else {
                val identity = CairnIdentity.generate()
                signer = DemoSigner(identity)
                publicKeyRaw = identity.publicKeyRaw
                keyAlias = DEMO_DEVICE_KEY_ALIAS
                Log.w(TAG, "CairnSession: SOFTWARE demo device key (hardware key unavailable)")
            }

            val config = SidecarEndpointConfig(
                host = "127.0.0.1",
                port = 5225.toUShort(),
                dbPath = "${filesDir.absolutePath}/simplex-db",
                filesDir = "${filesDir.absolutePath}/xftp",
                socksProxy = BUNDLED_TOR_SOCKS,
                // At-rest encryption (D0006 §3.5 / D0022 §2.2): opens the in-process libsimplex
                // chat DB with SQLCipher so the SMP-agent/chat databases (queue
                // secrets + message metadata) are AES-encrypted on disk. Demo
                // passphrase for now — DISTINCT from the storage passphrase above
                // (no cross-domain key reuse). v1 will derive this from the
                // user-unlocked Argon2id storage KEK via a domain-separated KDF,
                // never a hardcoded constant. NB the DB must be created encrypted
                // on a fresh install; an existing unencrypted DB cannot be opened
                // with a key (no SQLCipher header).
                dbKey = "cairn-demo-db-passphrase",
                maxRetries = 3.toUByte(),
            )
            val handle = SimplexAdapterHandle(storage, signer, keyAlias, publicKeyRaw, config)
            Log.i(TAG, "CairnSession bootstrapped (${publicKeyRaw.size}-byte op key)")
            return CairnSession(publicKeyRaw, handle)
        }
    }
}
