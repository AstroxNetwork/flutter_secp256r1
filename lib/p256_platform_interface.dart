import 'dart:typed_data';

import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'p256_method_channel.dart';

abstract class P256Platform extends PlatformInterface {
  /// Constructs a P256Platform.
  P256Platform() : super(token: _token);

  static final Object _token = Object();

  static P256Platform _instance = MethodChannelP256();

  /// The default instance of [P256Platform] to use.
  ///
  /// Defaults to [MethodChannelP256].
  static P256Platform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [P256Platform] when
  /// they register themselves.
  static set instance(P256Platform instance) {
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
}
