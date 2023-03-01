import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:agent_dart/agent/crypto/index.dart';
import 'package:agent_dart/bridge/ffi/ffi.dart';
import 'package:agent_dart/identity/der.dart';
import 'package:agent_dart/identity/p256.dart';
import 'package:tuple/tuple.dart';

import 'p256_platform_interface.dart';

class SecureP256 {
  const SecureP256._();

  static Future<P256PublicKey> getPublicKey(String tag) async {
    assert(tag.isNotEmpty);
    final raw = await SecureP256Platform.instance.getPublicKey(tag);
    // ECDSA starts with 0x04 and 65 length.
    if (raw.lengthInBytes == 65) {
      return P256PublicKey.fromRaw(raw);
    } else {
      return P256PublicKey.fromDer(raw);
    }
  }

  static Future<Uint8List> sign(String tag, Uint8List payload) async {
    assert(tag.isNotEmpty);
    assert(payload.isNotEmpty);
    final signature = await SecureP256Platform.instance.sign(tag, payload);
    if (isDerSignature(signature)) {
      return bytesUnwrapDerSignature(signature);
    } else {
      return signature; // As raw.
    }
  }

  static Future<bool> verify(
    Uint8List payload,
    P256PublicKey publicKey,
    Uint8List signature,
  ) {
    assert(payload.isNotEmpty);
    assert(signature.isNotEmpty);
    Uint8List rawKey = publicKey.rawKey;
    if (Platform.isAndroid && !isDerPublicKey(rawKey, oidP256)) {
      rawKey = bytesWrapDer(rawKey, oidP256);
    }
    if (!isDerSignature(signature)) {
      signature = bytesWrapDerSignature(signature);
    }
    return SecureP256Platform.instance.verify(
      payload,
      rawKey,
      signature,
    );
  }

  static Future<Uint8List> getSharedSecret(
      String tag, P256PublicKey publicKey) {
    assert(tag.isNotEmpty);
    Uint8List rawKey = publicKey.rawKey;
    if (Platform.isAndroid && !isDerPublicKey(rawKey, oidP256)) {
      rawKey = bytesWrapDer(rawKey, oidP256);
    }
    return SecureP256Platform.instance.getSharedSecret(tag, rawKey);
  }

  /// Return [iv, cipher].
  static Future<Tuple2<Uint8List, Uint8List>> encrypt({
    required Uint8List sharedSecret,
    required Uint8List message,
  }) async {
    assert(sharedSecret.isNotEmpty);
    assert(message.isNotEmpty);
    final sharedX = sharedSecret.sublist(0, 32);
    final iv = Uint8List.fromList(randomAsU8a(12));
    final cipher = await AgentDartFFI.impl.aes256GcmEncrypt(
      req: AesEncryptReq(
        key: sharedX,
        iv: Uint8List.fromList(iv),
        message: message,
      ),
    );
    return Tuple2(iv, cipher);
  }

  static Future<Uint8List> decrypt({
    required Uint8List sharedSecret,
    required Uint8List iv,
    required Uint8List cipher,
  }) async {
    assert(sharedSecret.isNotEmpty);
    assert(iv.lengthInBytes == 12);
    assert(cipher.isNotEmpty);
    final sharedX = sharedSecret.sublist(0, 32);
    final decryptedMessage256 = await AgentDartFFI.impl.aes256GcmDecrypt(
      req: AesDecryptReq(
        key: sharedX,
        iv: iv,
        cipherText: cipher,
      ),
    );
    return decryptedMessage256;
  }
}
