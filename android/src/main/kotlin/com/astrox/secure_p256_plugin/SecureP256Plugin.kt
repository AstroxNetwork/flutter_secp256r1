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
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.EncodedKeySpec
import java.security.spec.X509EncodedKeySpec


/** SecureP256Plugin */
class SecureP256Plugin : FlutterPlugin, MethodCallHandler {
    private lateinit var channel: MethodChannel
    private val storeProvider: String = "AndroidKeyStore"
    private val signatureAlgorithm: String = "SHA256withECDSA"
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
                    val keyPair = getPublicKeyFromAlias(alias)
                    result.success(keyPair.public.encoded)
                }

                "sign" -> {
                    val alias = call.argument<String>("tag")!!
                    val payload = call.argument<ByteArray>("payload")!!
                    val privateKey = getPublicKeyFromAlias(alias, throwIfNotExists = true).private
                    val signing = Signature.getInstance(signatureAlgorithm)
                    signing.initSign(privateKey)
                    signing.update(payload)
                    val signature = signing.sign()
                    result.success(signature)
                }

                "verify" -> {
                    val cPayload = call.argument<ByteArray>("payload")!!
                    val cSignature = call.argument<ByteArray>("signature")!!
                    val cPublicKey = call.argument<ByteArray>("publicKey")!!
                    val verifying = Signature.getInstance(signatureAlgorithm)
                    val publicKeySpec: EncodedKeySpec = X509EncodedKeySpec(cPublicKey)
                    val kf = KeyFactory.getInstance("EC")
                    val publicKey = kf.generatePublic(publicKeySpec)
                    verifying.initVerify(publicKey)
                    verifying.update(cPayload)
                    val verifyResult = verifying.verify(cSignature)
                    result.success(verifyResult)
                }

                else -> result.notImplemented()
            }
        } catch (e: Throwable) {
            result.error(e.javaClass.name, e.message, e.stackTrace.toString())
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

    private fun getPublicKeyFromAlias(alias: String, throwIfNotExists: Boolean = false): KeyPair {
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
            val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, storeProvider)
            val parameterSpec = KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).run {
                setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                setDigests(KeyProperties.DIGEST_SHA256)
                if (hasStrongBox() && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(true)
                }
                build()
            }
            kpg.initialize(parameterSpec)
            kpg.generateKeyPair()
        }
        return keyPair
    }
}
