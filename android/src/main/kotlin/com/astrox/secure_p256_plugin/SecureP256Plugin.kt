package com.astrox.secure_p256_plugin

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
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
        Security.removeProvider("BC")
        Security.insertProviderAt(Conscrypt.newProvider(), 1)
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
                    val privateKey = getKeyPairFromAlias(cAlias, throwIfNotExists = true).private
                    val signature = Signature.getInstance(signatureAlgorithm).run {
                        initSign(privateKey)
                        update(payload)
                        sign()
                    }
                    result.success(signature)
                }

                "verify" -> {
                    val cPayload = call.argument<ByteArray>("payload")!!
                    val cPublicKey = call.argument<ByteArray>("publicKey")!!
                    val cSignature = call.argument<ByteArray>("signature")!!
                    val verifyResult = Signature.getInstance(signatureAlgorithm).run {
                        val kf = KeyFactory.getInstance("EC")
                        val publicKeySpec: EncodedKeySpec = X509EncodedKeySpec(cPublicKey)
                        val publicKey = kf.generatePublic(publicKeySpec)
                        initVerify(publicKey)
                        update(cPayload)
                        verify(cSignature)
                    }
                    result.success(verifyResult)
                }

                "getSharedSecret" -> {
                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
                        result.error("getSharedSecret", "Unsupported API level", null)
                        return
                    }
                    val cAlias = call.argument<String>("tag")!!
                    val cPublicKey = call.argument<ByteArray>("publicKey")!!
                    val keyPair = getKeyPairFromAlias(cAlias, throwIfNotExists = true)
                    val kf = KeyFactory.getInstance("EC")
                    val publicKeySpec: EncodedKeySpec = X509EncodedKeySpec(cPublicKey)
                    val publicKey = kf.generatePublic(publicKeySpec)
                    val agreement = KeyAgreement.getInstance("ECDH", storeProvider)
                    agreement.init(keyPair.private)
                    agreement.doPhase(publicKey, true)
                    val sharedSecret = agreement.generateSecret()
                    result.success(sharedSecret)
                }

                else -> result.notImplemented()
            }
        } catch (e: Throwable) {
            result.error(e.javaClass.name, e.message, e.stackTraceToString())
        }
    }

    private fun hasStrongBox(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return applicationContext!!.packageManager.hasSystemFeature(
                PackageManager.FEATURE_STRONGBOX_KEYSTORE
            )
        }
        return false
    }

    private fun getKeyPairFromAlias(alias: String, throwIfNotExists: Boolean = false): KeyPair {
        val ks: KeyStore = KeyStore.getInstance(storeProvider).apply { load(null) }
        val keyPair: KeyPair = if (ks.containsAlias(alias)) {
            val entry = ks.getEntry(alias, null)
            if (entry !is KeyStore.PrivateKeyEntry) {
                throw TypeCastException()
            }
            KeyPair(entry.certificate.publicKey, entry.privateKey)
        } else if (throwIfNotExists) {
            throw KeyStoreException("No key was found with the alias $alias.")
        } else {
            val kpg: KeyPairGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, storeProvider)
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
                if (hasStrongBox() && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    // Not setting the strong box until we figure out if it's valid.
                    setIsStrongBoxBacked(true)
                }
            }.build()
            kpg.initialize(parameterSpec)
            kpg.generateKeyPair()
        }
        return keyPair
    }
}
