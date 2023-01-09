import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p256/p256_method_channel.dart';

void main() {
  MethodChannelP256 platform = MethodChannelP256();
  const MethodChannel channel = MethodChannel('p256');

  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    channel.setMockMethodCallHandler((MethodCall methodCall) async {
      return '42';
    });
  });

  tearDown(() {
    channel.setMockMethodCallHandler(null);
  });

  test('getPlatformVersion', () async {
    expect(await platform.getPlatformVersion(), '42');
  });
}
