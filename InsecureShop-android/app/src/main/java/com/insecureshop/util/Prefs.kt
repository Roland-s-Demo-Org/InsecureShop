package com.insecureshop.util

import android.content.Context
import android.content.SharedPreferences
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
    
    private const val KEY_ALIAS = "InsecureShopPasswordKey"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH = 128

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

    var password: String?
        get() {
            val encryptedPassword = sharedpreferences.getString("password", null)
            return if (encryptedPassword != null && encryptedPassword.isNotEmpty()) {
                try {
                    decryptPassword(encryptedPassword)
                } catch (e: Exception) {
                    // If decryption fails, return empty string
                    ""
                }
            } else {
                ""
            }
        }
        set(value) {
            if (value != null && value.isNotEmpty()) {
                try {
                    val encryptedPassword = encryptPassword(value)
                    sharedpreferences.edit().putString("password", encryptedPassword).apply()
                } catch (e: Exception) {
                    // If encryption fails, don't store the password
                    sharedpreferences.edit().remove("password").apply()
                }
            } else {
                sharedpreferences.edit().remove("password").apply()
            }
        }

    var productList: String?
        get() = sharedpreferences.getString("productList","")
        set(value) {
            sharedpreferences.edit().putString("productList", value).apply()
        }


    fun clearAll(){
        sharedpreferences.edit().clear().apply()
    }
    
    private fun getOrCreateSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
            )
            
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false)
                .build()
            
            keyGenerator.init(keyGenParameterSpec)
            return keyGenerator.generateKey()
        }
        
        return keyStore.getKey(KEY_ALIAS, null) as SecretKey
    }
    
    private fun encryptPassword(plaintext: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateSecretKey())
        
        val iv = cipher.iv
        val encryptedBytes = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        
        // Combine IV and encrypted data
        val combined = iv + encryptedBytes
        return Base64.encodeToString(combined, Base64.DEFAULT)
    }
    
    private fun decryptPassword(encrypted: String): String {
        val combined = Base64.decode(encrypted, Base64.DEFAULT)
        
        // Extract IV (first 12 bytes for GCM)
        val iv = combined.copyOfRange(0, 12)
        val encryptedBytes = combined.copyOfRange(12, combined.size)
        
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateSecretKey(), spec)
        
        val decryptedBytes = cipher.doFinal(encryptedBytes)
        return String(decryptedBytes, Charsets.UTF_8)
    }
}