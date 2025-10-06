package ru.surfstudio.otp_autofill

import android.content.Context
import android.content.ContextWrapper
import android.content.pm.PackageManager
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

private const val HASH_TYPE = "SHA-256"
private const val NUM_HASHED_BYTES = 9
private const val NUM_BASE64_CHAR = 11

/**
 * Helper class to generate the app's SMS hash key used for SMS Retriever API.
 * Based on Google's example implementation.
 */
class AppSignatureHelper(context: Context) : ContextWrapper(context) {

    fun getAppSignatures(): List<String> {
        return try {
            val pkgName = packageName
            val pkgManager = packageManager
            // ✅ FIX: use safe-call to handle possible null signatures
            val signatures = pkgManager
                .getPackageInfo(pkgName, PackageManager.GET_SIGNATURES)
                .signatures

            // Kotlin 1.9 requires safe access to nullable arrays
            signatures?.mapNotNull { hash(pkgName, it.toCharsString()) } ?: emptyList()
        } catch (e: PackageManager.NameNotFoundException) {
            emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun hash(packageName: String, signature: String): String? {
        val appInfo = "$packageName $signature"
        return try {
            val messageDigest = MessageDigest.getInstance(HASH_TYPE)
            messageDigest.update(appInfo.toByteArray(StandardCharsets.UTF_8))
            val hashSignature = messageDigest.digest().copyOfRange(0, NUM_HASHED_BYTES)
            var base64Hash =
                Base64.encodeToString(hashSignature, Base64.NO_PADDING or Base64.NO_WRAP)
            base64Hash.substring(0, NUM_BASE64_CHAR)
        } catch (e: NoSuchAlgorithmException) {
            null
        }
    }
}
