import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'p256_platform_interface.dart';

/// An implementation of [P256Platform] that uses method channels.
class MethodChannelP256 extends P256Platform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('p256');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>('getPlatformVersion');
    return version;
  }
}
