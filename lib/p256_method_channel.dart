import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'p256_platform_interface.dart';
import 'src/constants.dart';

/// An implementation of [P256Platform] that uses method channels.
class MethodChannelP256 extends P256Platform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('p256');

  @override
  Future<Uint8List> getPublicKey(String tag) async {
    final keyBytes = await methodChannel.invokeMethod(
      Methods.getPublicKey,
      {'tag': tag},
    );
    return keyBytes;
  }

  @override
  Future<Uint8List> sign(String tag, Uint8List payload) async {
    final signature = await methodChannel.invokeMethod(
      Methods.sign,
      {'tag': tag, 'payload': payload},
    );
    return signature;
  }

  @override
  Future<bool> verify(
    Uint8List payload,
    Uint8List publicKey,
    Uint8List signature,
  ) async {
    final result = await methodChannel.invokeMethod<bool>(
      Methods.verify,
      {
        'payload': payload,
        'publicKey': publicKey,
        'signature': signature,
      },
    );
    return result ?? false;
  }
}
