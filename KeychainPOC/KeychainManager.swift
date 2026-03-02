import Foundation
import Security

enum KeychainError: LocalizedError {
    case keyGenerationFailed(String)
    case keyNotFound
    case publicKeySaveFailed(OSStatus)
    case unexpectedError(OSStatus)

    var errorDescription: String? {
        switch self {
        case .keyGenerationFailed(let msg):
            return "Key generation failed: \(msg)"
        case .keyNotFound:
            return "Key not found in Keychain"
        case .publicKeySaveFailed(let status):
            return "Failed to save public key: OSStatus \(status)"
        case .unexpectedError(let status):
            return "Unexpected Keychain error: OSStatus \(status)"
        }
    }
}

final class KeychainManager {

    static let privateKeyTag = "com.poc.KeychainPOC.privateKey"
    static let publicKeyTag  = "com.poc.KeychainPOC.publicKey"

    // MARK: - Generate RSA Key Pair (Fixed)

    /// Generates an RSA 2048-bit key pair and stores both keys in the Keychain.
    ///
    /// Fixes applied:
    /// 1. `kSecAttrApplicationTag` uses `Data`, not `String`
    /// 2. Public key is saved manually via `SecItemAdd` because
    ///    `SecKeyCreateRandomKey` only persists the private key
    static func generateKeyPair() throws {
        // Delete any existing keys first to avoid duplicates
        deleteKeyPair()

        // FIX #1: Tags must be Data, not String
        let privateTagData = privateKeyTag.data(using: .utf8)!
        let publicTagData  = publicKeyTag.data(using: .utf8)!

        let privateKeyParams: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: privateTagData
        ]

        // FIX #2: We do NOT include kSecPublicKeyAttrs with kSecAttrIsPermanent
        // because SecKeyCreateRandomKey ignores it — the public key is NOT persisted.
        let parameters: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: privateKeyParams
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error) else {
            let msg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw KeychainError.keyGenerationFailed(msg)
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw KeychainError.keyGenerationFailed("Could not derive public key")
        }

        // FIX #2: Manually save the public key to the Keychain
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: publicTagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecValueRef as String: publicKey,
            kSecAttrIsPermanent as String: true
        ]

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.publicKeySaveFailed(status)
        }
    }

    // MARK: - Find Key

    /// Retrieves a key from the Keychain by its tag.
    /// FIX #1: Tag is converted to `Data` before querying.
    static func findKey(_ tagName: String) -> SecKey? {
        let tagData = tagName.data(using: .utf8)!

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag as String: tagData,
            kSecReturnRef as String: true
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess, let ref = result else {
            return nil
        }
        // Safe: SecItemCopyMatching with kSecReturnRef returns a SecKey
        return unsafeBitCast(ref, to: SecKey.self)
    }

    // MARK: - Convenience Accessors

    static func getPrivateKey() -> SecKey? {
        findKey(privateKeyTag)
    }

    static func getPublicKey() -> SecKey? {
        // Option A: Look up persisted public key directly
        if let key = findKey(publicKeyTag) {
            return key
        }
        // Option B: Derive from private key as fallback
        if let privateKey = getPrivateKey() {
            return SecKeyCopyPublicKey(privateKey)
        }
        return nil
    }

    // MARK: - Delete Keys

    static func deleteKeyPair() {
        deleteKey(privateKeyTag)
        deleteKey(publicKeyTag)
    }

    static func deleteKey(_ tagName: String) {
        let tagData = tagName.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Diagnostic: Check Key Existence

    static func keyExists(_ tagName: String) -> (exists: Bool, status: OSStatus) {
        let tagData = tagName.data(using: .utf8)!

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag as String: tagData,
            kSecReturnRef as String: true
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return (status == errSecSuccess, status)
    }

    // MARK: - Quick Encrypt/Decrypt Test

    static func testEncryptDecrypt() throws -> String {
        guard let publicKey = getPublicKey(),
              let privateKey = getPrivateKey() else {
            throw KeychainError.keyNotFound
        }

        let testMessage = "Hello from KeychainPOC!"
        let testData = testMessage.data(using: .utf8)!

        var encryptError: Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(
            publicKey,
            .rsaEncryptionPKCS1,
            testData as CFData,
            &encryptError
        ) else {
            let msg = encryptError?.takeRetainedValue().localizedDescription ?? "Unknown"
            throw KeychainError.keyGenerationFailed("Encryption failed: \(msg)")
        }

        var decryptError: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(
            privateKey,
            .rsaEncryptionPKCS1,
            encryptedData,
            &decryptError
        ) else {
            let msg = decryptError?.takeRetainedValue().localizedDescription ?? "Unknown"
            throw KeychainError.keyGenerationFailed("Decryption failed: \(msg)")
        }

        let decryptedMessage = String(data: decryptedData as Data, encoding: .utf8) ?? "???"
        return decryptedMessage
    }
}
