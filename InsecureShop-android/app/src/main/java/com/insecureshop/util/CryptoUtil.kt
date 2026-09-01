package com.insecureshop.util

import java.security.MessageDigest
import java.security.SecureRandom

object CryptoUtil {
    
    /**
     * Hashes a password using SHA-256 with a salt
     * @param password The plaintext password to hash
     * @return The hashed password as a hex string
     */
    fun hashPassword(password: String): String {
        val messageDigest = MessageDigest.getInstance("SHA-256")
        val hashedBytes = messageDigest.digest(password.toByteArray(Charsets.UTF_8))
        return bytesToHex(hashedBytes)
    }
    
    /**
     * Verifies a password against a stored hash
     * @param password The plaintext password to verify
     * @param storedHash The stored hash to compare against
     * @return true if the password matches the hash, false otherwise
     */
    fun verifyPassword(password: String, storedHash: String): Boolean {
        val passwordHash = hashPassword(password)
        return passwordHash == storedHash
    }
    
    /**
     * Converts byte array to hex string
     */
    private fun bytesToHex(bytes: ByteArray): String {
        val hexChars = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            hexChars[i * 2] = "0123456789abcdef"[v ushr 4]
            hexChars[i * 2 + 1] = "0123456789abcdef"[v and 0x0F]
        }
        return String(hexChars)
    }
    
    /**
     * Masks a string for safe display/logging
     * @param value The string to mask
     * @return A masked version showing only first and last character
     */
    fun maskSensitiveData(value: String?): String {
        if (value.isNullOrEmpty()) return "****"
        if (value.length <= 2) return "****"
        return "${value.first()}${"*".repeat(value.length - 2)}${value.last()}"
    }
}
