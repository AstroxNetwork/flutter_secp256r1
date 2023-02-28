import 'dart:typed_data';

import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'p256_method_channel.dart';

abstract class SecureP256Platform extends PlatformInterface {
  /// Constructs a P256Platform.
  SecureP256Platform() : super(token: _token);

  static final Object _token = Object();

  static SecureP256Platform _instance = SecureP256Channel();

  /// The default instance of [SecureP256Platform] to use.
  ///
  /// Defaults to [SecureP256Channel].
  static SecureP256Platform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [SecureP256Platform] when
  /// they register themselves.
  static set instance(SecureP256Platform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<Uint8List> getPublicKey(String tag) {
    return _instance.getPublicKey(tag);
  }

  Future<Uint8List> sign(String tag, Uint8List payload) {
    return _instance.sign(tag, payload);
  }

  Future<bool> verify(
    Uint8List payload,
    Uint8List publicKey,
    Uint8List signature,
  ) {
    return _instance.verify(payload, publicKey, signature);
  }

  Future<Uint8List> getSharedSecret(String tag, Uint8List publicKey) {
    return _instance.getSharedSecret(tag, publicKey);
  }
}
