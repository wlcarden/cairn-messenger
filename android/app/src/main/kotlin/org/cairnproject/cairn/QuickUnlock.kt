// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Opt-in biometric / device-credential **quick unlock** (D0029). It wraps the
 * user's unlock PASSPHRASE under a hardware-auth-bound AndroidKeyStore AES-GCM
 * key — the storage KEK is never touched (it stays `NeverExport`, derived in
 * Rust, D0022 §2.4). The passphrase remains the root secret and the only
 * recovery; this is an additive *alternate gate*, default OFF.
 *
 * Security posture (D0029 §4): when DISABLED, no wrapped secret exists on disk —
 * byte-identical to passphrase-only (a seized powered-off device yields pure
 * ciphertext). When ENABLED, a passphrase ciphertext sits in `quick-unlock.bin`,
 * releasable only by StrongBox/TEE after a successful Class-3 biometric or
 * lockscreen-credential auth while the device is unlocked. The key is per-use
 * (a fresh auth every time), unlocked-device-required, and invalidated by a new
 * biometric enrollment (so a coerced new fingerprint can't open it).
 */
object QuickUnlock {
    private const val TAG = "CairnFfi"
    private const val KEY_ALIAS = "cairn-quick-unlock-v1"
    private const val BLOB_NAME = "quick-unlock.bin"
    private const val KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    private const val IV_LEN = 12

    /** Class-3 biometric OR the lockscreen PIN/pattern/password (D0029 §5). */
    private const val AUTHENTICATORS = BIOMETRIC_STRONG or DEVICE_CREDENTIAL

    /** True when the device can satisfy at least one allowed authenticator. */
    fun isAvailable(activity: FragmentActivity): Boolean =
        BiometricManager.from(activity).canAuthenticate(AUTHENTICATORS) ==
            BiometricManager.BIOMETRIC_SUCCESS

    /** True when a wrapped-passphrase blob exists (quick unlock is enrolled). */
    fun isEnrolled(filesDir: File): Boolean = File(filesDir, BLOB_NAME).exists()

    /** Turn quick unlock OFF: delete the blob + the Keystore key (D0029 §2). */
    fun disable(filesDir: File) {
        runCatching { File(filesDir, BLOB_NAME).delete() }
        runCatching {
            KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(KEY_ALIAS)
        }
        Log.i(TAG, "quick-unlock: disabled")
    }

    /**
     * Enroll: authenticate, then AES-GCM-encrypt [passphrase] under a fresh
     * hardware key and persist `iv ‖ ct`. Call right after a successful
     * passphrase unlock, when the passphrase is known-correct and in hand.
     * [onResult] (`ok`, `error`) runs on the main thread.
     */
    fun enroll(
        activity: FragmentActivity,
        passphrase: ByteArray,
        onResult: (Boolean, String?) -> Unit,
    ) {
        val cipher = try {
            Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, generateKey()) }
        } catch (e: Exception) {
            Log.e(TAG, "quick-unlock: keygen failed", e)
            onResult(false, "couldn't set up the secure hardware key")
            return
        }
        authenticate(
            activity,
            cipher,
            title = "Enable quick unlock",
            subtitle = "Confirm it's you to store your passphrase in secure hardware",
            onError = { onResult(false, it) },
            onSuccess = { authed ->
                try {
                    val blob = authed.iv + authed.doFinal(passphrase)
                    File(activity.filesDir, BLOB_NAME).writeBytes(blob)
                    Log.i(TAG, "quick-unlock: enrolled (${blob.size} bytes)")
                    onResult(true, null)
                } catch (e: Exception) {
                    Log.e(TAG, "quick-unlock: wrap failed", e)
                    onResult(false, "couldn't store the wrapped passphrase")
                }
            },
        )
    }

    /**
     * Unlock: authenticate, then decrypt the blob back to the passphrase.
     * [onPassphrase] receives the plaintext passphrase bytes (feed to the
     * session unlock); [onError] receives a message (cancel / no blob /
     * invalidation). Both run on the main thread. A key invalidated by a
     * biometric change self-heals: the blob is purged and the user falls back to
     * the passphrase (and may re-enroll).
     */
    fun unlock(
        activity: FragmentActivity,
        onPassphrase: (ByteArray) -> Unit,
        onError: (String) -> Unit,
    ) {
        val blob = runCatching { File(activity.filesDir, BLOB_NAME).readBytes() }.getOrNull()
        if (blob == null || blob.size <= IV_LEN) {
            onError("quick unlock isn't set up")
            return
        }
        val iv = blob.copyOfRange(0, IV_LEN)
        val ct = blob.copyOfRange(IV_LEN, blob.size)
        val cipher = try {
            val key = loadKey() ?: run { onError("quick unlock isn't set up"); return }
            Cipher.getInstance(TRANSFORM)
                .apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv)) }
        } catch (e: KeyPermanentlyInvalidatedException) {
            Log.w(TAG, "quick-unlock: key invalidated (biometric change) — purging")
            disable(activity.filesDir)
            onError("Quick unlock was reset by a security change — use your passphrase")
            return
        } catch (e: Exception) {
            Log.e(TAG, "quick-unlock: cipher init failed", e)
            onError("couldn't start quick unlock")
            return
        }
        authenticate(
            activity,
            cipher,
            title = "Unlock Cairn",
            subtitle = "Use your fingerprint or screen lock",
            onError = onError,
            onSuccess = { authed ->
                try {
                    onPassphrase(authed.doFinal(ct))
                } catch (e: Exception) {
                    Log.e(TAG, "quick-unlock: unwrap failed", e)
                    onError("couldn't read the wrapped passphrase")
                }
            },
        )
    }

    /** Show the BiometricPrompt bound to [cipher]; route the result. */
    private fun authenticate(
        activity: FragmentActivity,
        cipher: Cipher,
        title: String,
        subtitle: String,
        onError: (String) -> Unit,
        onSuccess: (Cipher) -> Unit,
    ) {
        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(code: Int, msg: CharSequence) =
                    onError(msg.toString())

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val c = result.cryptoObject?.cipher
                    if (c == null) onError("no secure cipher in the auth result") else onSuccess(c)
                }
                // onAuthenticationFailed = one bad attempt; the prompt stays up.
            },
        )
        // With DEVICE_CREDENTIAL allowed, the credential IS the fallback, so a
        // negative button is disallowed (setNegativeButtonText would throw).
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(AUTHENTICATORS)
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    /**
     * Generate (replacing any prior) the auth-bound AES-256-GCM key (D0029 §3):
     * user-auth per-use, unlocked-device-required, invalidated by a new
     * biometric enrollment, StrongBox-backed when the device has it.
     */
    private fun generateKey(): SecretKey {
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            // timeout 0 = a fresh auth for EVERY use (no validity window).
            .setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
            .setUnlockedDeviceRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()

        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        return try {
            gen.init(spec(strongBox = true))
            gen.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            Log.w(TAG, "quick-unlock: StrongBox unavailable — using the TEE")
            gen.init(spec(strongBox = false))
            gen.generateKey()
        }
    }

    private fun loadKey(): SecretKey? = runCatching {
        KeyStore.getInstance(KEYSTORE).apply { load(null) }.getKey(KEY_ALIAS, null) as? SecretKey
    }.getOrNull()
}
