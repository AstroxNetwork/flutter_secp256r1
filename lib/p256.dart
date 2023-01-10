import 'dart:typed_data';

import 'p256_platform_interface.dart';

class P256 {
  Future<Uint8List> getPublicKey(String tag) {
    return P256Platform.instance.getPublicKey(tag);
  }

  Future<Uint8List> sign(String tag, Uint8List payload) {
    return P256Platform.instance.sign(tag, payload);
  }

  Future<bool> verify(
    Uint8List payload,
    Uint8List publicKey,
    Uint8List signature,
  ) {
    return P256Platform.instance.verify(payload, publicKey, signature);
  }
}
