#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint secp256r1.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'secp256r1'
  s.version          = '0.1.0'
  s.summary          = 'A Flutter plugin that support secp256r1 by Secure Enclave,'
  s.description      = <<-DESC
A new Flutter plugin project.
                       DESC
  s.homepage         = 'https://astrox.me'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'AstroxNetwork' => 'dev@astrox.network' }
  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '11.3'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'
end
