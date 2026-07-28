package com.insecureshop.contentProvider

import android.content.ContentProvider
import android.content.ContentValues
import android.content.UriMatcher
import android.content.pm.PackageManager
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Binder
import android.os.Process
import com.insecureshop.util.Prefs


class InsecureShopProvider : ContentProvider() {

    companion object {
        var uriMatcher: UriMatcher? = null
        const val URI_CODE: Int = 100
    }

    override fun onCreate(): Boolean {
        uriMatcher = UriMatcher(UriMatcher.NO_MATCH)
        uriMatcher?.addURI("com.insecureshop.provider", "insecure", URI_CODE)
        return true
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?
    ): Cursor? {
        if (uriMatcher?.match(uri) == URI_CODE) {
            // Verify the calling package has the same signature as this app
            val callingUid = Binder.getCallingUid()
            val callingPackages = context?.packageManager?.getPackagesForUid(callingUid)
            val myPackageName = context?.packageName
            
            // Only allow access from the same application
            val isAuthorized = callingPackages?.any { pkg ->
                pkg == myPackageName || isSameSignature(pkg)
            } ?: false
            
            if (!isAuthorized) {
                // Return empty cursor for unauthorized callers
                return MatrixCursor(arrayOf("username"))
            }
            
            // Never expose password via ContentProvider - only return username
            val cursor = MatrixCursor(arrayOf("username"))
            val username = Prefs.username
            if (!username.isNullOrEmpty()) {
                cursor.addRow(arrayOf(username))
            }
            return cursor
        }
        return null
    }
    
    /**
     * Verify that the calling package has the same signing certificate as this app
     */
    private fun isSameSignature(callingPackage: String): Boolean {
        return try {
            val myPackageName = context?.packageName ?: return false
            val pm = context?.packageManager ?: return false
            
            val callingSignatures = pm.getPackageInfo(
                callingPackage,
                PackageManager.GET_SIGNATURES
            ).signatures
            
            val mySignatures = pm.getPackageInfo(
                myPackageName,
                PackageManager.GET_SIGNATURES
            ).signatures
            
            // Compare signatures
            callingSignatures.contentEquals(mySignatures)
        } catch (e: Exception) {
            false
        }
    }

    override fun getType(uri: Uri): String? {
        return null
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? {
        return null
    }

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int {
        return 0
    }

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?
    ): Int {
        return 0
    }
}