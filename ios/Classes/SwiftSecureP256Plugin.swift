import Foundation
import Flutter
import LocalAuthentication
import UIKit

public class SwiftSecureP256Plugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "astrox_secure_p256_plugin", binaryMessenger: registrar.messenger())
        let instance = SwiftSecureP256Plugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }
    
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
            case "getPublicKey":
                do {
                    let param = call.arguments as? Dictionary<String, Any>
                    let tag = param!["tag"] as! String
                    var password : String? = nil
                    if let pwd = param!["password"] as? String {
                        password = pwd
                    }

                    let key = try getPublicKey(tag: tag, password: password)!
                    result(FlutterStandardTypedData(bytes: key))
                } catch {
                    result(FlutterError(code: "getPublicKey", message: error.localizedDescription, details: "\(error)"))
                }
            case "sign" :
                do {
                    let param = call.arguments as? Dictionary<String, Any>
                    let tag = param!["tag"] as! String
                    let message = param!["payload"] as! FlutterStandardTypedData
                    var password : String? = nil
                    if let pwd = param!["password"] as? String {
                        password = pwd
                    }

                    let signature = try sign(
                        tag: tag,
                        password: password,
                        message: message.data
                    )!
                    result(FlutterStandardTypedData(bytes: signature))
                } catch {
                    result(FlutterError(code: "sign", message: error.localizedDescription, details: "\(error)"))
                }
            case "verify" :
                do {
                    let param = call.arguments as? Dictionary<String, Any>
                    let payload = (param!["payload"] as! FlutterStandardTypedData).data
                    let publicKey = (param!["publicKey"] as! FlutterStandardTypedData).data
                    let signature = (param!["signature"] as! FlutterStandardTypedData).data
                    let verified = try verify(
                        payload: payload,
                        publicKey: publicKey,
                        signature: signature
                    )

                    result(verified)
                } catch {
                    result(FlutterError(code: "verify", message: error.localizedDescription, details: "\(error)"))
                }
            default:
                result(FlutterMethodNotImplemented)
        }
    }
    
    func generateKeyPair(tag: String, password: String?) throws -> SecKey {
        let tagData = tag.data(using: .utf8)
        let flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        var accessError: Unmanaged<CFError>?
        let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &accessError
        )
        if let error = accessError {
            throw error.takeRetainedValue() as Error
        }
        
        let parameter : CFDictionary
        var parameterTemp: Dictionary<String, Any>
        
        if let tagData = tagData {
            parameterTemp = [
                kSecAttrKeyType as String           : kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String     : 256,
                kSecPrivateKeyAttrs as String       : [
                    kSecAttrIsPermanent as String       : true,
                    kSecAttrApplicationTag as String    : tagData,
                    kSecAttrAccessControl as String     : accessControl!
                ]
            ]
            if TARGET_OS_SIMULATOR != 0 {
                parameterTemp[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
            }
            if flags.contains(.applicationPassword) {
                let context = LAContext()
                var newPassword : Data?
                if let password = password, !password.isEmpty {
                    newPassword = password.data(using: .utf8)
                }
                context.setCredential(newPassword, type: .applicationPassword)
                parameterTemp[kSecUseAuthenticationContext as String] = context
            }
            
            parameter = parameterTemp as CFDictionary
            var secKeyCreateRandomKeyError: Unmanaged<CFError>?
            guard let secKey = SecKeyCreateRandomKey(parameter, &secKeyCreateRandomKeyError)
            else {
                throw secKeyCreateRandomKeyError!.takeRetainedValue() as Error
            }
            
            return secKey
        } else {
            throw CustomError.runtimeError("Invalid TAG") as Error
        }
    }
    
    func getPublicKey(tag: String, password: String?) throws -> Data? {
        let secKey : SecKey
        let publicKey : SecKey
        
        do {
            if isKeyCreated(tag: tag, password: password) {
                secKey = try getSecKey(tag: tag, password: password)!
            } else {
                secKey = try generateKeyPair(tag: tag, password: password)
            }
            publicKey = SecKeyCopyPublicKey(secKey)!
        } catch {
            throw error
        }
        
        var error: Unmanaged<CFError>?
        if let keyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? {
            return keyData
        } else {
            return nil
        }
    }
    
    func sign(tag: String, password: String?, message: Data) throws -> Data? {
        let secKey : SecKey
        do {
            secKey = try getSecKey(tag: tag, password: password)!
        } catch {
            throw error
        }
        
        var error: Unmanaged<CFError>?
        guard let signData = SecKeyCreateSignature(
            secKey,
            SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256,
            message as CFData,
            &error
        ) else {
            if let e = error {
                throw e.takeUnretainedValue() as Error
            }
            throw CustomError.runtimeError("Cannot sign the payload")
        }
        return signData as Data
    }
    
    func verify(payload: Data, publicKey: Data, signature: Data) throws -> Bool {
        let newPublicParams: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        guard let newPublicKey = SecKeyCreateWithData(
            publicKey as CFData,
            newPublicParams as CFDictionary,
            nil
        ) else {
            return false
        }
        
        let verify = SecKeyVerifySignature(
            newPublicKey,
            SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256,
            payload as CFData,
            signature as CFData,
            nil
        )
        return verify
    }
    
    internal func getSecKey(tag: String, password: String?) throws -> SecKey?  {
        let tagData = tag.data(using: .utf8)!
        var query: [String: Any] = [
            kSecClass as String                 : kSecClassKey,
            kSecAttrApplicationTag as String    : tagData,
            kSecAttrKeyType as String           : kSecAttrKeyTypeEC,
            kSecMatchLimit as String            : kSecMatchLimitOne ,
            kSecReturnRef as String             : true
        ]
        
        if let password = password, !password.isEmpty {
            let context = LAContext()
            let newPassword = password.data(using: .utf8)
            context.setCredential(newPassword, type: .applicationPassword)
            query[kSecUseAuthenticationContext as String] = context
        }
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw NSError(
                domain: NSOSStatusErrorDomain,
                code: Int(status),
                userInfo: [NSLocalizedDescriptionKey: SecCopyErrorMessageString(status,nil) ?? "Undefined error"]
            )
        }
        
        if let item = item {
            return (item as! SecKey)
        } else {
            return nil
        }
    }
    
    internal func isKeyCreated(tag: String, password: String?) -> Bool {
        do {
            let result = try getSecKey(tag: tag, password: password)
            return result != nil ? true : false
        } catch {
            return false
        }
    }
}

enum CustomError: Error {

    case runtimeError(String)

    func get() -> String {
        switch self {
        case .runtimeError(let desc):
            return desc
        }
    }
}

extension CustomError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .runtimeError:
            return NSLocalizedString("\(self.get())", comment: "Custom Error")
        }
    }
}
