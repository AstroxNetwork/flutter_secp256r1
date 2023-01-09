import 'package:flutter_test/flutter_test.dart';
import 'package:p256/p256.dart';
import 'package:p256/p256_platform_interface.dart';
import 'package:p256/p256_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockP256Platform
    with MockPlatformInterfaceMixin
    implements P256Platform {

  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final P256Platform initialPlatform = P256Platform.instance;

  test('$MethodChannelP256 is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelP256>());
  });

  test('getPlatformVersion', () async {
    P256 p256Plugin = P256();
    MockP256Platform fakePlatform = MockP256Platform();
    P256Platform.instance = fakePlatform;

    expect(await p256Plugin.getPlatformVersion(), '42');
  });
}
