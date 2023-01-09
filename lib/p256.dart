
import 'p256_platform_interface.dart';

class P256 {
  Future<String?> getPlatformVersion() {
    return P256Platform.instance.getPlatformVersion();
  }
}
