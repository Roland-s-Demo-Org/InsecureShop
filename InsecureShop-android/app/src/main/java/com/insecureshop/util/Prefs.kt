package com.insecureshop.util

import android.content.Context
import android.content.SharedPreferences

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

    /**
     * Stores the hashed password (not plaintext)
     * Use setPasswordHash() to store a password securely
     */
    var passwordHash: String?
        get() = sharedpreferences.getString("passwordHash","")
        private set(value) {
            sharedpreferences.edit().putString("passwordHash", value).apply()
        }

    /**
     * Deprecated: Direct password access removed for security
     * Use verifyPassword() to check credentials
     */
    @Deprecated("Password is now stored as a hash. Use verifyPassword() instead.", 
                ReplaceWith("verifyPassword(password)"))
    var password: String?
        get() = null  // Never return plaintext password
        set(value) {
            // Hash the password before storing
            if (!value.isNullOrEmpty()) {
                passwordHash = CryptoUtil.hashPassword(value)
            }
        }

    /**
     * Sets the password by hashing it first
     * @param plainPassword The plaintext password to hash and store
     */
    fun setPasswordHash(plainPassword: String) {
        passwordHash = CryptoUtil.hashPassword(plainPassword)
    }

    /**
     * Verifies a plaintext password against the stored hash
     * @param plainPassword The plaintext password to verify
     * @return true if the password matches, false otherwise
     */
    fun verifyPassword(plainPassword: String): Boolean {
        val storedHash = passwordHash
        if (storedHash.isNullOrEmpty()) return false
        return CryptoUtil.verifyPassword(plainPassword, storedHash)
    }

    var productList: String?
        get() = sharedpreferences.getString("productList","")
        set(value) {
            sharedpreferences.edit().putString("productList", value).apply()
        }


    fun clearAll(){
        sharedpreferences.edit().clear().apply()
    }
}