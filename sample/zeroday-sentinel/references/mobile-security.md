# Mobile Application Security Reference

Security checks for iOS (Swift/Objective-C), Android (Kotlin/Java), React Native, Flutter, and cross-platform mobile apps.

## Data Storage Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Secrets in SharedPreferences/UserDefaults | API keys, tokens in unencrypted storage | HIGH | Use Android Keystore / iOS Keychain for sensitive data. Use EncryptedSharedPreferences on Android |
| Hardcoded API keys | API keys in source code or config files | CRITICAL | Use build-time injection via environment variables. Store in secure backend, not in app binary |
| Sensitive data in app backups | Unencrypted backups containing tokens/credentials | HIGH | Android: `android:allowBackup="false"`. iOS: exclude from iCloud backup. Use Keychain with `kSecAttrAccessibleWhenUnlocked` |
| Logging sensitive data | Logging tokens, passwords, PII | HIGH | Disable verbose logging in production. Strip log statements in release builds. Use ProGuard/R8 on Android |
| Clipboard exposure | Copying sensitive data to clipboard | MEDIUM | Set `secureTextEntry` on sensitive fields. Clear clipboard on app background. Use `UIPasteboard.general.items = []` on iOS |
| Database without encryption | SQLite databases without encryption | HIGH | Use SQLCipher for SQLite encryption. On iOS, use Core Data with NSFileProtectionComplete |
| Cache containing sensitive data | Sensitive responses cached on disk | MEDIUM | Disable HTTP caching for sensitive APIs: `URLCache.shared.removeAllCachedResponses()`. Use `no-store` Cache-Control |

**Remediation — Secure storage (Android):**
```kotlin
// EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val securePrefs = EncryptedSharedPreferences.create(
    context, "secure_prefs", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

securePrefs.edit().putString("auth_token", token).apply()
```

**Remediation — Secure storage (iOS):**
```swift
import Security

func saveToKeychain(key: String, value: String) throws {
    let data = value.data(using: .utf8)!
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: key,
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    ]
    SecItemDelete(query as CFDictionary)
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else { throw KeychainError.saveFailed(status) }
}
```

## Network Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing certificate pinning | No SSL pinning for API connections | HIGH | Implement certificate pinning. Pin to leaf or intermediate cert. Have a rotation plan |
| Allowing HTTP cleartext | `NSAppTransportSecurity` allows cleartext / `android:usesCleartextTraffic="true"` | HIGH | Enforce HTTPS only. Remove cleartext exceptions. Use `network_security_config.xml` on Android |
| Disabled TLS verification | `TrustManager` that accepts all certs / `NSAllowsArbitraryLoads` | CRITICAL | Never disable TLS verification in production. Use proper certificate validation |
| Sensitive data in URL | Tokens or PII in URL path/query (logged by proxies, ISPs) | HIGH | Send sensitive data in request body or headers. Use POST for sensitive operations |
| Missing network security config | No `network_security_config.xml` on Android | MEDIUM | Create `network_security_config.xml` with `cleartextTrafficPermitted="false"` and certificate pins |

**Remediation — Network security config (Android):**
```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2027-01-01">
            <pin digest="SHA-256">base64EncodedPin=</pin>
            <pin digest="SHA-256">backupPin=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

**Remediation — Certificate pinning (iOS):**
```swift
// Using TrustKit
TrustKit.initSharedInstance(withConfiguration: [
    kTSKSwizzleNetworkDelegates: false,
    kTSKPinnedDomains: [
        "api.example.com": [
            kTSKEnforcePinning: true,
            kTSKPublicKeyHashes: [
                "base64EncodedHash1=",
                "base64EncodedHash2=",  // backup pin
            ],
        ]
    ]
])
```

## Authentication Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Biometric auth without server validation | Local-only biometric check without backend verification | HIGH | Use biometric auth to unlock Keychain/Keystore-stored credentials, then authenticate with server |
| Token stored in plaintext | Auth tokens in UserDefaults/SharedPreferences | HIGH | Store tokens in Keychain (iOS) or EncryptedSharedPreferences/Keystore (Android) |
| Missing token refresh | No silent token refresh mechanism | MEDIUM | Implement token refresh flow. Refresh before expiration. Handle 401 responses by refreshing |
| Auto-login without re-authentication | App auto-logs in without any re-verification | MEDIUM | Require biometric/PIN re-verification for sensitive operations (payment, profile changes) |
| Persistent login across installs | Auth state survives app uninstall/reinstall | MEDIUM | Clear Keychain on first launch after install (iOS). Clear EncryptedSharedPreferences |

## App Binary Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Debug build in production | `android:debuggable="true"` or debug signing | CRITICAL | Ensure release builds: `debuggable false`, ProGuard/R8 enabled, release signing |
| Missing code obfuscation | No ProGuard/R8 (Android) or no Swift compilation optimization | MEDIUM | Enable R8/ProGuard with custom rules. Use Swift whole-module optimization |
| Root/jailbreak detection missing | No check for compromised devices | MEDIUM | Detect root/jailbreak and warn users. Block sensitive operations on compromised devices |
| Absence of tamper detection | No integrity checks for the app binary | MEDIUM | Implement app attestation: Play Integrity API (Android), App Attest (iOS) |
| Exported components without protection | Android Activities/Services with `exported=true` without permissions | HIGH | Set `exported="false"` for internal components. Use `android:permission` for exported components |

**Remediation — Android build hardening (build.gradle):**
```kotlin
android {
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            isDebuggable = false
        }
    }
}
```

## WebView Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| JavaScript enabled in WebView with user content | `setJavaScriptEnabled(true)` loading untrusted content | HIGH | Disable JavaScript when not needed. Validate URLs before loading. Use `setAllowFileAccess(false)` |
| JavaScript interface with sensitive methods | `addJavascriptInterface` exposing app internals | CRITICAL | Minimize exposed methods. Use `@JavascriptInterface` annotation (Android). Validate origin before exposing |
| File access in WebView | `setAllowFileAccess(true)`, `setAllowUniversalAccessFromFileURLs(true)` | HIGH | Disable file access: `setAllowFileAccess(false)`, `setAllowFileAccessFromFileURLs(false)` |
| Mixed content in WebView | Loading HTTP content in HTTPS WebView | MEDIUM | Set `setMixedContentMode(MIXED_CONTENT_NEVER_ALLOW)` |

## Deep Link Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unvalidated deep link parameters | Deep link data used without validation | HIGH | Validate all deep link parameters. Use allowlists for actions and destinations |
| Deep link hijacking | Custom URL scheme without verification | HIGH | Use App Links (Android) / Universal Links (iOS) with domain verification instead of custom URL schemes |
| Sensitive data in deep links | Tokens or PII passed via deep links | HIGH | Use short-lived, one-time-use tokens in deep links. Never pass credentials |
| Open redirect via deep links | Deep link redirecting to arbitrary URLs | HIGH | Validate redirect destinations against an allowlist of trusted domains |

## React Native / Flutter Specific

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Secrets in JavaScript bundle | API keys in React Native JS bundle (extractable) | CRITICAL | Use `react-native-config` for build-time injection. Store secrets server-side. Never hardcode in JS |
| Hermes bytecode not obfuscated | React Native Hermes bytecode easily decompilable | MEDIUM | Enable Hermes. Use additional obfuscation tools. Don't rely on obfuscation for security |
| Insecure AsyncStorage | Sensitive data in React Native AsyncStorage (unencrypted) | HIGH | Use `react-native-keychain` for sensitive data instead of AsyncStorage |
| Flutter platform channel without validation | Platform channels accepting unvalidated data | HIGH | Validate all data crossing platform channels. Use typed channels |
| Dart source maps in release | Source maps included in Flutter release builds | MEDIUM | Ensure `--no-tree-shake-icons` and `--obfuscate --split-debug-info` for release builds |

**Remediation — React Native secure storage:**
```javascript
import * as Keychain from 'react-native-keychain';

// Store securely
await Keychain.setGenericPassword('authToken', token, {
  accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  securityLevel: Keychain.SECURITY_LEVEL.SECURE_HARDWARE,
});

// Retrieve
const credentials = await Keychain.getGenericPassword();
if (credentials) {
  const token = credentials.password;
}
```
