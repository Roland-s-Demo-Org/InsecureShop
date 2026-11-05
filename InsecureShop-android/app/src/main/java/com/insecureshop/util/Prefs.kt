package com.insecureshop.util

import android.annotation.TargetApi
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object Prefs {

    lateinit var sharedpreferences: SharedPreferences
    var prefs : Prefs? = null

    fun getInstance(context: Context): Prefs {
        if (prefs == null) {
            sharedpreferences =
                context.getSharedPreferences("Prefs", Context.MODE_PRIVATE)
            prefs = this
        }
        return prefs!!
    }

    var data: String?
        get() = sharedpreferences.getString("data","")
        set(value) {
            sharedpreferences.edit().putString("data", value).apply()
        }

    var username: String?
        get() = sharedpreferences.getString("username","")
        set(value) {
            sharedpreferences.edit().putString("username", value).apply()
        }

    // The password is never written in plaintext. On API 23+ it is encrypted with an AES-256/GCM
    // key held in the Android Keystore (non-exportable, not included in backups). On older
    // platforms, where such keys are unavailable, it is retained in memory only.
    private const val PASSWORD_KEY = "password"
    private const val ENCRYPTED_PREFIX = "enc:"
    private const val KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "insecureshop_prefs_password_key"
    private const val GCM_TAG_BITS = 128
    private var memoryPassword: String? = null

    @TargetApi(Build.VERSION_CODES.M)
    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE)
        keyStore.load(null)
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    private fun encrypt(plain: String): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            val cipherText = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
            ENCRYPTED_PREFIX +
                    Base64.encodeToString(cipher.iv, Base64.NO_WRAP) + ":" +
                    Base64.encodeToString(cipherText, Base64.NO_WRAP)
        } catch (e: Exception) {
            null
        }
    }

    private fun decrypt(stored: String): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return null
        return try {
            val parts = stored.removePrefix(ENCRYPTED_PREFIX).split(":")
            if (parts.size != 2) return null
            val iv = Base64.decode(parts[0], Base64.NO_WRAP)
            val cipherText = Base64.decode(parts[1], Base64.NO_WRAP)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
            String(cipher.doFinal(cipherText), Charsets.UTF_8)
        } catch (e: Exception) {
            null
        }
    }

    var password: String?
        get() {
            val stored = sharedpreferences.getString(PASSWORD_KEY, "")
            if (stored.isNullOrEmpty()) return memoryPassword ?: ""
            if (!stored.startsWith(ENCRYPTED_PREFIX)) {
                // Legacy plaintext value: migrate it to protected storage and remove the plaintext.
                password = stored
                return stored
            }
            return decrypt(stored) ?: memoryPassword ?: ""
        }
        set(value) {
            memoryPassword = value
            val editor = sharedpreferences.edit()
            val encrypted = if (value.isNullOrEmpty()) null else encrypt(value)
            if (encrypted != null) {
                editor.putString(PASSWORD_KEY, encrypted)
            } else {
                editor.remove(PASSWORD_KEY)
            }
            editor.apply()
        }

    var productList: String?
        get() = sharedpreferences.getString("productList","")
        set(value) {
            sharedpreferences.edit().putString("productList", value).apply()
        }


    fun clearAll(){
        memoryPassword = null
        sharedpreferences.edit().clear().apply()
    }
}