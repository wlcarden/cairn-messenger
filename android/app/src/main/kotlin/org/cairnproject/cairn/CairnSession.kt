// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
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
 * Real, device-bound [StrongBoxKeyMaterial] for the storage KEK (D0022 §2.2 /
 * D0020 §3.4) — replaces the former demo constant. The 32 bytes are an HMAC
 * computed by a NON-EXPORTABLE AndroidKeyStore HMAC-SHA256 key that lives in
 * StrongBox (the Pixel's Titan M2) when available, else the TEE; the key never
 * leaves secure hardware, so the material can only be reproduced on THIS device.
 *
 * `cairn-storage` mixes this into every category DEK
 * (`DEK = HKDF(KEK ‖ material, salt, info=category)`, key_provider.rs), so the
 * third at-rest factor — device — is now real: a seized encrypted store can't be
 * decrypted off-device even with the correct passphrase (the StrongBox HMAC is
 * not reproducible elsewhere). The key requires NO user authentication (the
 * passphrase is the user factor; this is the device factor), so a normal unlock
 * needs no biometric prompt, and the material is STABLE across launches (the key
 * persists) — a changing material would make the store undecryptable.
 *
 * **Migration:** a store created under the old demo constant (`0x2A…`) cannot be
 * opened once this is in force (its DEKs differ) — fresh installs only, the same
 * caveat the at-rest DB encryption carries (D0026 §12).
 *
 * **Consequence (by design):** the at-rest data is device-bound — losing the
 * device (or its StrongBox key) means the local data is unrecoverable even with
 * the passphrase. That is the intended defense against off-device brute force;
 * identity recovery (D0005 Shamir) is a separate concern from local at-rest data.
 */
class StrongBoxStorageKeyMaterial : StrongBoxKeyMaterial {
    @Volatile private var loggedLevel = false

    override fun strongboxMaterial(): ByteArray = try {
        Mac.getInstance(MAC_ALG).run {
            init(materialKey())
            doFinal(MATERIAL_DOMAIN.toByteArray())
        }
    } catch (e: Exception) {
        Log.e(TAG, "storage StrongBox material unavailable", e)
        throw CairnFfiException.SidecarFailure()
    }

    override fun isUnlocked(): Boolean = true

    /** Load (or first-launch generate) the non-exportable HMAC material key. */
    private fun materialKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val key = (ks.getKey(KEY_ALIAS, null) as? SecretKey) ?: generateMaterialKey()
        if (!loggedLevel) {
            loggedLevel = true
            Log.i(TAG, "storage material key securityLevel=${securityLevel(key)}")
        }
        return key
    }

    private fun generateMaterialKey(): SecretKey {
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN,
        )
            .setKeySize(256)
            .setDigests(KeyProperties.DIGEST_SHA256)
            // No user-auth + no unlocked-device-required: this is the DEVICE
            // factor, gated by the passphrase, not a second presence gate — so a
            // normal unlock (and the background recv loop) never needs a prompt.
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE)
        return runCatching { gen.init(spec(strongBox = true)); gen.generateKey() }
            .getOrElse { e ->
                Log.w(TAG, "storage material key: StrongBox unavailable (${e.message}) — TEE")
                gen.init(spec(strongBox = false))
                gen.generateKey()
            }
    }

    /** Authoritative secure-hardware level of [key] (StrongBox / TEE / software). */
    private fun securityLevel(key: SecretKey): String = runCatching {
        val info = SecretKeyFactory.getInstance(key.algorithm, KEYSTORE)
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                else -> "level=${info.securityLevel}"
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) "secure-hardware" else "software"
        }
    }.getOrDefault("unknown")

    private companion object {
        const val TAG = "CairnFfi"
        const val KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "cairn-storage-kek-material-v1"
        const val MAC_ALG = "HmacSHA256"
        const val MATERIAL_DOMAIN = "cairn-v1-storage-kek-material"
    }
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
    /** The opened encrypted store — backs the contact list + message history. */
    val storage: StorageHandle,
    val handle: SimplexAdapterHandle,
) {
    /**
     * Re-key the encrypted store from [old] to [new] (D0030 §3 —
     * change-passphrase): re-encrypts every record under the new
     * passphrase-derived DEKs + a fresh salt, atomically, then swaps the live
     * DEK cache so this session keeps working. The device StrongBox material is
     * unchanged (a fresh [StrongBoxStorageKeyMaterial] reproduces it), and the
     * libsimplex DB is untouched (its key is a stored record, re-encrypted in
     * place — D0030 §2). Throws on a wrong [old] (`StorageDecryptFailed`) with
     * no mutation. Blocking (Argon2id ×2 + a full re-encrypt) — call off the
     * main thread.
     */
    fun changePassphrase(old: ByteArray, new: ByteArray) {
        storage.changePassphrase(old, new, StrongBoxStorageKeyMaterial())
    }

    companion object {
        private const val TAG = "CairnFfi"

        /**
         * Bootstrap the session under [filesDir]. Uses the **hardware-backed
         * Ed25519 device key** ([KeystoreEd25519Signer]) when the platform can
         * provide one, falling back to the software demo identity otherwise so
         * the app never bricks on a key-provisioning gap.
         */
        fun bootstrap(filesDir: File, passphrase: ByteArray): CairnSession {
            val storage = StorageHandle.open(
                "${filesDir.absolutePath}/store.db",
                // Two real at-rest factors now (D0022 §2.2): the user's unlock
                // passphrase → Argon2id KEK, mixed with a device-bound StrongBox
                // HMAC (StrongBoxStorageKeyMaterial) into each category DEK — so a
                // seized store needs BOTH the passphrase AND this device's
                // secure hardware (no longer a demo constant).
                passphrase,
                StrongBoxStorageKeyMaterial(),
            )
            // The storage layer does NOT verify the passphrase on open (a wrong
            // passphrase yields a wrong KEK that only fails on a sealed read), so
            // validate it against an encrypted canary; first launch writes it.
            // Throws on a wrong passphrase.
            validateOrInitPassphrase(storage)

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
                // At-rest encryption (D0006 §3.5 / D0022 §2.2): opens the
                // in-process libsimplex chat DB with SQLCipher (queue secrets +
                // message metadata AES-encrypted on disk). The key is a RANDOM
                // value stored inside cairn-storage (D0030 §2) — readable only
                // once the passphrase-gated storage is unlocked, but STABLE across
                // a passphrase change, so change-passphrase re-keys storage alone
                // and never rekeys this DB (fresh installs only).
                dbKey = simplexDbKey(storage),
                maxRetries = 3.toUByte(),
            )
            val handle = SimplexAdapterHandle(storage, signer, keyAlias, publicKeyRaw, config)
            Log.i(TAG, "CairnSession bootstrapped (${publicKeyRaw.size}-byte op key)")
            return CairnSession(publicKeyRaw, storage, handle)
        }

        /**
         * Validate the unlock passphrase against an encrypted canary (D0022):
         * the storage layer derives a KEK from any passphrase without verifying
         * it — a wrong passphrase only fails when a sealed record is read — so we
         * seal a known marker under the KEK and read it back. First launch
         * writes it. Throws [IllegalStateException] on a wrong passphrase.
         */
        private fun validateOrInitPassphrase(storage: StorageHandle) {
            val read = runCatching { storage.get(IDENTITY_CATEGORY, UNLOCK_CANARY_ID) }
            if (read.isFailure) {
                // Sealed-record read failed → wrong KEK → wrong passphrase.
                throw IllegalStateException("wrong passphrase")
            }
            val existing = read.getOrNull()
            if (existing == null) {
                storage.put(IDENTITY_CATEGORY, UNLOCK_CANARY_ID, UNLOCK_CANARY_VALUE)
                Log.i(TAG, "unlock: first launch — passphrase set")
            } else if (!existing.contentEquals(UNLOCK_CANARY_VALUE)) {
                throw IllegalStateException("wrong passphrase")
            } else {
                Log.i(TAG, "unlock: passphrase OK")
            }
        }

        /**
         * The SQLCipher DB key for the in-process libsimplex chat DB — a RANDOM
         * 32-byte key generated once and STORED inside cairn-storage (D0030 §2),
         * not derived from the passphrase. Reading it requires the unlocked
         * storage (so it stays passphrase-gated, transitively), but its value is
         * STABLE across a passphrase change — so `change_passphrase` re-keys
         * cairn-storage alone and never touches the libsimplex DB. Hex-encoded
         * (SQLCipher applies its own PBKDF2). First launch mints + persists it.
         */
        private fun simplexDbKey(storage: StorageHandle): String {
            runCatching { storage.get(IDENTITY_CATEGORY, SIMPLEX_DB_KEY_ID) }
                .getOrNull()
                ?.takeIf { it.isNotEmpty() }
                ?.let { return it.toHex() }
            val fresh = ByteArray(32).also { SecureRandom().nextBytes(it) }
            storage.put(IDENTITY_CATEGORY, SIMPLEX_DB_KEY_ID, fresh)
            Log.i(TAG, "simplex db key: minted + stored (first launch)")
            return fresh.toHex()
        }

        /** Must match `cairn_storage::categories::IDENTITY`. */
        private const val IDENTITY_CATEGORY = "identity"

        /** Record id (in IDENTITY) of the stored random SimpleX DB key (D0030 §2). */
        private val SIMPLEX_DB_KEY_ID = "cairn-simplex-db-key-v1".toByteArray()

        /** Record id + value of the encrypted passphrase canary. */
        private val UNLOCK_CANARY_ID = "cairn-unlock-canary-v1".toByteArray()
        private val UNLOCK_CANARY_VALUE = "cairn-unlock-ok".toByteArray()
    }
}
