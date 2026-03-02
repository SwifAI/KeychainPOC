# KeychainPOC

A proof-of-concept iOS app demonstrating correct RSA key pair generation and persistence using the iOS Keychain.

## Problem

When generating RSA key pairs with `SecKeyCreateRandomKey`, keys were lost after killing the app. Three bugs were identified:

### Bug 1: `kSecAttrApplicationTag` expects `Data`, not `String`

```swift
// WRONG
kSecAttrApplicationTag as String: "com.example.tag"

// CORRECT
kSecAttrApplicationTag as String: "com.example.tag".data(using: .utf8)!
```

Passing a `String` causes a type mismatch between the store and query paths in the Keychain's SQLite backend. The key may appear to save, but `SecItemCopyMatching` fails to find it on subsequent lookups.

### Bug 2: `SecKeyCreateRandomKey` does NOT persist the public key

`SecKeyCreateRandomKey` only returns and persists the **private key**. Setting `kSecAttrIsPermanent: true` in `kSecPublicKeyAttrs` is effectively ignored.

**Solution A** (recommended): Derive the public key on demand from the private key:

```swift
let privateKey = findKey(privateKeyTag)
let publicKey = SecKeyCopyPublicKey(privateKey)
```

**Solution B**: Manually save the public key with `SecItemAdd`:

```swift
let addQuery: [String: Any] = [
    kSecClass as String: kSecClassKey,
    kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
    kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
    kSecValueRef as String: publicKey,
    kSecAttrIsPermanent as String: true
]
SecItemAdd(addQuery as CFDictionary, nil)
```

### Bug 3: Missing entitlements on Simulator

Without a Keychain entitlements file, the iOS Simulator can silently fail keychain operations with error `-34018` (`errSecMissingEntitlement`). Adding the Keychain Sharing capability generates the required entitlements file.

## Project Structure

```
KeychainPOC/
├── KeychainPOCApp.swift        # App entry point
├── ContentView.swift           # Test UI with Generate / Check / Encrypt / Delete buttons
├── KeychainManager.swift       # Corrected Keychain implementation
├── KeychainPOC.entitlements    # Keychain access group entitlement
└── Info.plist
```

## How to Test

1. Open `KeychainPOC.xcodeproj` in Xcode
2. Run on a simulator or device
3. Tap **Generate Key Pair** — logs should show keys saved successfully
4. Tap **Check Keys Exist** — both private and public keys should be FOUND
5. Tap **Test Encrypt / Decrypt** — confirms the keys work end-to-end
6. **Kill the app** (swipe up from app switcher)
7. **Relaunch the app** — on launch it automatically checks if keys survived
8. Both keys should still show as FOUND

## Requirements

- iOS 17.0+
- Xcode 16.0+
- Swift 5.9+
