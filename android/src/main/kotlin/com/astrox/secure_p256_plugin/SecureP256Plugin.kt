package com.astrox.secure_p256_plugin

import android.content.Context
//import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.conscrypt.Conscrypt
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement


/** SecureP256Plugin */
class SecureP256Plugin : FlutterPlugin, MethodCallHandler {
    companion object {
        const val storeProvider: String = "AndroidKeyStore"
        const val signatureAlgorithm: String = "SHA256withECDSA"
    }

    init {
        Security.insertProviderAt(BouncyCastleProvider(), 1)
        Security.addProvider(Conscrypt.newProvider())
    }

    private lateinit var channel: MethodChannel
    private var applicationContext: Context? = null

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        applicationContext = flutterPluginBinding.applicationContext
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "astrox_secure_p256_plugin")
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        applicationContext = null
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        try {
            when (call.method) {
                "getPublicKey" -> {
                    val alias = call.argument<String>("tag")!!
                    val keyPair = getKeyPairFromAlias(alias)
                    result.success(keyPair.public.encoded)
                }

                "sign" -> {
                    val cAlias = call.argument<String>("tag")!!
                    val payload = call.argument<ByteArray>("payload")!!
                    val signature = sign(cAlias, payload)
                    result.success(signature)
                }

                "verify" -> {
                    val cPublicKey = call.argument<ByteArray>("publicKey")!!
                    val cPayload = call.argument<ByteArray>("payload")!!
                    val cSignature = call.argument<ByteArray>("signature")!!
                    val verifyResult = verify(cPublicKey, cPayload, cSignature)
                    result.success(verifyResult)
                }

                "getSharedSecret" -> {
                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
                        result.error("getSharedSecret", "Unsupported API level", null)
                        return
                    }
                    val cAlias = call.argument<String>("tag")!!
                    val cPublicKey = call.argument<ByteArray>("publicKey")!!
                    val sharedSecret = ecdh(cAlias, cPublicKey)
                    result.success(sharedSecret)
                }

                else -> result.notImplemented()
            }
        } catch (e: Throwable) {
            result.error(e.javaClass.name, e.message, e.stackTraceToString())
        }
    }

    /**
     * Obtain the keystore private key entry reference from the given key.
     *
     * Reading the private key data is invalid in the runtime, it's protected by the operating system.
     *
     * @param [alias] The key of which key should be obtained.
     * @return The entry reference.
     * @throws GeneralSecurityException If the key data could not be access by security reasons.
     * @throws InvalidKeyException If the key data is unable to be read from the underlying provider.
     * @throws TypeCastException If the entry is not [KeyStore.PrivateKeyEntry].
     */
    @Throws(GeneralSecurityException::class, InvalidKeyException::class, TypeCastException::class)
    @Synchronized
    private fun obtainPrivateKeyEntryFromAliasWithRetry(
        alias: String,
        keyStore: KeyStore? = null
    ): KeyStore.PrivateKeyEntry {
        val ks: KeyStore = keyStore ?: KeyStore.getInstance(storeProvider).apply { load(null) }
        val entry = ks.getEntry(alias, null)
        if (entry !is KeyStore.PrivateKeyEntry) {
            throw TypeCastException()
        }
        return entry
    }

    private fun obtainPrivateKeyEntryFromAlias(alias: String, keyStore: KeyStore? = null): KeyStore.PrivateKeyEntry {
        return try {
            obtainPrivateKeyEntryFromAliasWithRetry(alias, keyStore)
        } catch (ignored: InvalidKeyException) {
            /** Retry when [InvalidKeyException] occurred. */
            obtainPrivateKeyEntryFromAliasWithRetry(alias, keyStore)
        }
    }

    @Throws(KeyStoreException::class)
    @Synchronized
    private fun getKeyPairFromAlias(alias: String, throwIfNotExists: Boolean = false): KeyPair {
        val ks: KeyStore = KeyStore.getInstance(storeProvider).apply { load(null) }
        val keyPair: KeyPair = if (ks.containsAlias(alias)) {
            val entry = obtainPrivateKeyEntryFromAlias(alias, ks)
            KeyPair(entry.certificate.publicKey, entry.privateKey)
        } else if (throwIfNotExists) {
            throw KeyStoreException("No key was found with the alias $alias.")
        } else {
            val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, storeProvider)
            var properties = KeyProperties.PURPOSE_ENCRYPT or
                    KeyProperties.PURPOSE_DECRYPT or
                    KeyProperties.PURPOSE_SIGN or
                    KeyProperties.PURPOSE_VERIFY
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                properties = properties or KeyProperties.PURPOSE_AGREE_KEY
            }
            val parameterSpec = KeyGenParameterSpec.Builder(alias, properties).apply {
                setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                setDigests(KeyProperties.DIGEST_SHA256)
                // Not setting the strong box until we figure out if it's valid.
                //if (hasStrongBox() && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                //  setIsStrongBoxBacked(true)
                //}
            }.build()
            kpg.initialize(parameterSpec)
            kpg.generateKeyPair()
        }
        return keyPair
    }

    @Synchronized
    private fun sign(alias: String, payload: ByteArray): ByteArray {
        val privateKey = obtainPrivateKeyEntryFromAlias(alias).privateKey
        val signature = Signature.getInstance(signatureAlgorithm)
        signature.initSign(privateKey)
        signature.update(payload)
        return signature.sign()
    }

    @Synchronized
    private fun verify(publicKeyBytes: ByteArray, payload: ByteArray, signatureBytes: ByteArray): Boolean {
        val kf = KeyFactory.getInstance("EC")
        val publicKeySpec: EncodedKeySpec = X509EncodedKeySpec(publicKeyBytes)
        val key = kf.generatePublic(publicKeySpec)
        val signature = Signature.getInstance(signatureAlgorithm)
        signature.initVerify(key)
        signature.update(payload)
        return signature.verify(signatureBytes)
    }

    @Synchronized
    private fun ecdh(alias: String, otherPublicKey: ByteArray): ByteArray {
        val entry = obtainPrivateKeyEntryFromAlias(alias)
        val kf = KeyFactory.getInstance("EC")
        val publicKeySpec: EncodedKeySpec = X509EncodedKeySpec(otherPublicKey)
        val publicKey = kf.generatePublic(publicKeySpec)
        val agreement = KeyAgreement.getInstance("ECDH", storeProvider)
        agreement.init(entry.privateKey)
        agreement.doPhase(publicKey, true)
        return agreement.generateSecret()
    }

//    private fun hasStrongBox(): Boolean {
//        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
//            return applicationContext!!.packageManager.hasSystemFeature(
//                PackageManager.FEATURE_STRONGBOX_KEYSTORE
//            )
//        }
//        return false
//    }
}
