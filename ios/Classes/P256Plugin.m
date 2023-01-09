#import "P256Plugin.h"
#if __has_include(<p256/p256-Swift.h>)
#import <p256/p256-Swift.h>
#else
// Support project import fallback if the generated compatibility header
// is not copied when this plugin is created as a library.
// https://forums.swift.org/t/swift-static-libraries-dont-copy-generated-objective-c-header/19816
#import "p256-Swift.h"
#endif

@implementation P256Plugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftP256Plugin registerWithRegistrar:registrar];
}
@end
