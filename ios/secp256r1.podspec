#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint secp256r1.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'secp256r1'
  s.version          = '1.0.0'
  s.summary          = 'Secure P256.'
  s.description      = <<-DESC
A Flutter plugin that support secp256r1 by Secure Enclave.
                       DESC
  s.homepage         = 'https://github.com/AstroxNetwork/flutter_secp256r1'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'AstroxNetwork' => 'dev@astrox.network' }
  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '12.0'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'
end
