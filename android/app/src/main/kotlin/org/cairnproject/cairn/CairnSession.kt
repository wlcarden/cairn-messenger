// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import uniffi.cairn_uniffi.AttestationCertificate
import uniffi.cairn_uniffi.CairnFfiException
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
 * **NOT the v1 hardened path.** The real identity signs in StrongBox via an
 * `AndroidKeyStoreSigner` (D0020 §3.4 / D0028 — pending); here a SOFTWARE
 * Ed25519 key (Android 13+ platform provider) stands in so the UI + the
 * bundled-Tor transport can be exercised end-to-end. The same key serves as
 * BOTH the device key (it signs the envelope) and the operational key (the
 * envelope's sender field) — a simplification valid for a 1:1 transport/UI
 * demo, where the two peers exchange their pubkeys alongside the invitation.
 */

private const val ED25519 = "Ed25519"
const val DEMO_DEVICE_KEY_ALIAS = "cairn-demo-op-key"

/** The trailing bytes of an Ed25519 X.509 SPKI are the 32-byte raw public key. */
private const val ED25519_RAW_KEY_LEN = 32

/**
 * A Keystore-backed Ed25519 demo identity. The key is generated in the Android
 * Keystore (TEE-backed) under [DEMO_DEVICE_KEY_ALIAS] and persists there across
 * launches; the private key never leaves the Keystore (signing routes through
 * it). The v1 hardening adds StrongBox + key attestation (D0020 §3.4 / D0028).
 */
class CairnIdentity private constructor(
    private val privateKey: PrivateKey,
    /** Raw 32-byte Ed25519 public key — the envelope operational + device pubkey. */
    val publicKeyRaw: ByteArray,
) {
    /** Ed25519 signature (64 bytes) over [payload] via the Keystore key. */
    fun sign(payload: ByteArray): ByteArray =
        Signature.getInstance(ED25519).run {
            initSign(privateKey)
            update(payload)
            sign()
        }

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"

        /** Load the existing Keystore identity, or generate one under the alias. */
        fun loadOrCreate(): CairnIdentity {
            val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            if (ks.containsAlias(DEMO_DEVICE_KEY_ALIAS)) {
                val priv = ks.getKey(DEMO_DEVICE_KEY_ALIAS, null) as PrivateKey
                val pub = ks.getCertificate(DEMO_DEVICE_KEY_ALIAS).publicKey.encoded
                return CairnIdentity(priv, pub.rawEd25519())
            }
            val kpg = KeyPairGenerator.getInstance(ED25519, KEYSTORE)
            kpg.initialize(
                KeyGenParameterSpec.Builder(
                    DEMO_DEVICE_KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                ).build(),
            )
            val kp = kpg.generateKeyPair()
            return CairnIdentity(kp.private, kp.public.encoded.rawEd25519())
        }

        /** The trailing 32 bytes of the Ed25519 X.509 SPKI = the raw public key. */
        private fun ByteArray.rawEd25519(): ByteArray =
            copyOfRange(size - ED25519_RAW_KEY_LEN, size)
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
    val identity: CairnIdentity,
    val handle: SimplexAdapterHandle,
) {
    companion object {
        private const val TAG = "CairnFfi"

        /** Bootstrap the demo session under [filesDir]. */
        fun bootstrap(filesDir: File): CairnSession {
            val identity = CairnIdentity.loadOrCreate()
            val signer = DemoSigner(identity)
            val storage = StorageHandle.open(
                "${filesDir.absolutePath}/store.db",
                // Demo passphrase — the real one is user-entered at unlock.
                "cairn-demo-passphrase".toByteArray(),
                DemoKeyMaterial(),
            )
            val config = SidecarEndpointConfig(
                host = "127.0.0.1",
                port = 5225.toUShort(),
                dbPath = "${filesDir.absolutePath}/simplex-db",
                filesDir = "${filesDir.absolutePath}/xftp",
                socksProxy = BUNDLED_TOR_SOCKS,
                maxRetries = 3.toUByte(),
            )
            val handle = SimplexAdapterHandle(
                storage,
                signer,
                DEMO_DEVICE_KEY_ALIAS,
                identity.publicKeyRaw,
                config,
            )
            Log.i(TAG, "CairnSession bootstrapped (demo identity ${identity.publicKeyRaw.size}-byte op key)")
            return CairnSession(identity, handle)
        }
    }
}
