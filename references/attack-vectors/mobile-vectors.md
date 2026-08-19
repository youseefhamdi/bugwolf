# Mobile Attack Vectors (Android / iOS)

Aligned to **OWASP MASVS / MASWE / MASTG** control groups: `MASVS-STORAGE`, `MASVS-CRYPTO`, `MASVS-AUTH`, `MASVS-NETWORK`, `MASVS-PLATFORM`, `MASVS-CODE`, `MASVS-RESILIENCE`, `MASVS-PRIVACY`. Work with the `mobile-client-agent`.

## 1. Android — Exported Components & Intent Redirection (MASVS-PLATFORM)

Exported activities/receivers/services are entry points any app can invoke.

```bash
# Enumerate exported components
apktool d target.apk -o /tmp/apk/
grep -nE 'android:exported="true"' /tmp/apk/AndroidManifest.xml
# or with aapt/jadx
jadx -d /tmp/jadx target.apk
grep -rn "exported" /tmp/apk/AndroidManifest.xml
```

**Intent redirection:** a component that takes an intent and forwards it (embedded intent, `startActivity(intent)`, `sendBroadcast`) → attacker-supplied intent reaches a protected component.
```bash
adb shell am start -n com.target/.RedirectActivity --es "forward" "intent:#Intent;component=com.target/.AdminActivity;S.secret=1;end"
```

**Component hijacking:** implicit intents without `android:exported="false"` → a malicious app declares the same intent-filter and steals the intent (and any data/token in it).

**PendingIntent abuse:** a `PendingIntent` created with a mutable flag + attacker-controllable extras → fill-in of the embedded intent's component/action.

## 2. Deep Links & URL Schemes (MASVS-PLATFORM)

```bash
# Find schemes
grep -nE 'android:scheme|android:host|android:pathPrefix|android:pathPattern' /tmp/apk/AndroidManifest.xml
plutil -p /tmp/ipa/Payload/*.app/Info.plist | grep -A3 CFBundleURLSchemes
```

- **Scheme hijack:** register the same custom scheme → steal auth-callback tokens/authorization codes.
- **Parameter injection:** deep link params flow into a WebView load, a file open, a payment, or a redirect. Test `myapp://host/path?url=javascript:...`, `?redirect=https://evil`, `?file=../../`.
- **iOS universal link / Android App Link** downgrade: if the server's `apple-app-site-association` / `assetlinks.json` validation is weak, or the host is compromised, links can be re-routed.

```bash
adb shell am start -a android.intent.action.VIEW -d "myapp://pay?amount=0&to=attacker" com.target
```

## 3. WebView Exploitation (MASVS-PLATFORM / MASVS-CODE)

- **JS bridge:** `addJavascriptInterface` / `@JavascriptInterface` exposes Java objects to any JS the WebView loads. If a deep link or injected content can load attacker JS, it's RCE in the app context.
```javascript
// enumerate bridge
for (var k in window) { try { console.log(k, window[k]) } catch(e){} }
```
- **`loadUrl("javascript:" + userInput)` / `evaluateJavascript(userInput)`** — direct JS injection.
- **Missing URL validation:** WebView loads arbitrary schemes (`file://`, `intent://`, `content://`) → local file read or intent launch.
- **`setAllowFileAccess(true)` + `setAllowFileAccessFromFileURLs(true)`** → local file read from remote content.
- **iOS `WKWebView`:** `WKScriptMessageHandler` bridges; check `universalLinks`, `allowUniversalAccessFromFileURLs`, and custom scheme handlers.

## 4. Storage & Secrets (MASVS-STORAGE)

```bash
# Android — world-readable/backup leaks
grep -rniE "MODE_WORLD_READABLE|MODE_WORLD_WRITABLE|allowBackup=\"true\"" /tmp/apk/AndroidManifest.xml /tmp/jadx
grep -rniE "getSharedPreferences|openFileOutput|SQLiteDatabase|ContentResolver" /tmp/jadx --include="*.java"

# iOS — file protection & keychain
plutil -p /tmp/ipa/Payload/*.app/Info.plist | grep -iE "NSFileProtection|dataProtectionClass"
grep -rniE "kSecAttrAccessibleAlways|kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly" /tmp/ipa/

# Hardcoded secrets across both
grep -rniE "api[_-]?key|secret|token|password|BEGIN .*PRIVATE KEY|AKIA|ghp_|sk_live_|xox[bp]-" /tmp/apk /tmp/ipa /tmp/jadx
```

- **Backup extraction (Android):** `adb backup -apk -shared com.target` → restore with `abe` and read SharedPreferences/SQLite.
- **Log leakage:** `Log.d/i/w` of tokens/PII; `adb logcat` during auth flows.
- **Screenshot/flags:** `FLAG_SECURE` absent on sensitive screens → OCR leakage, task-switcher exposure.

## 5. Network & TLS (MASVS-NETWORK / MASVS-CRYPTO)

```bash
# Cleartext / weak config
grep -rniE "usesCleartextTraffic|cleartextTrafficPermitted" /tmp/apk/AndroidManifest.xml /tmp/apk/res/xml/*
grep -rniE "NSAllowsArbitraryLoads|NSAllowsLocalNetworking|NSExceptionDomains" /tmp/ipa/Payload/*.app/Info.plist
```

- **Cleartext traffic** → MITM credential/token theft.
- **Cert pinning bypass** (Frida/objection):
```bash
frida -U -f com.target -l /path/to/ssl_pinning_bypass.js --no-pause
objection -g com.target explore -s "android sslpinning disable"
```
- **Weak crypto:** ECB mode, hardcoded AES keys/IVs, `SHA1`/`MD5`, predictable PRNG, hardcoded JWT signing secrets.
- **Hostname verification disabled:** custom `TrustManager`/`HostnameVerifier` that returns `true`.

## 6. Auth & Authorization (MASVS-AUTH)

- **Biometric bypass:** `setDeviceCredentialAllowed(true)` / `BiometricPrompt` with `CryptoObject` missing or a weak callback → downgrade to device PIN, or bypass the crypto gate.
- **Session/token persistence:** tokens in SharedPreferences/NSUserDefaults with no encryption; refresh-token reuse.
- **Insecure auth flows:** OAuth PKCE missing; authorization code accepted cross-app; token leakage in WebView redirects/deep links.
- **Local auth fallback:** app honors a `biometric=false` / `fallback=true` parameter from an exported component.

## 7. Reverse Engineering & Tampering (MASVS-RESILIENCE)

- **Runtime instrumentation:** Frida/objection to hook methods, dump memory, read decrypted traffic.
- **Integrity checks bypass:** hook root/emulator/frida detection (`frida`, `Magisk`, `SafetyNet`/`Play Integrity`), patch smali/`.so` checks.
- **Jailbreak/root detection only:** detection without response is resilience theater; test the actual response (exit vs. continue).

## 8. iOS-Specific (MASVS-PLATFORM)

- **Keychain groups / entitlements:** shared keychain access group lets a sibling app read secrets.
- **App extensions:** share/notification/widget extensions with weaker isolation leak data.
- **`NSUserDefaults` suite sharing, pasteboard sniffing** (`UIPasteboard`) → cross-app data theft.
- **Jailbreak:** `cycript`, `Frida`, `flexdecrypt` to dump decrypted binary, patch checks.

## Grep Patterns

```bash
grep -rniE "addJavascriptInterface|evaluateJavascript|loadUrl\(\"javascript|setAllowFileAccess|setAllowUniversalAccess|WebView\(" /tmp/jadx /tmp/apk
grep -rniE "exported=\"true\"|grantUriPermissions|intent-filter|android:scheme|usesCleartextTraffic" /tmp/apk/AndroidManifest.xml
grep -rniE "getSharedPreferences|openFileOutput|MODE_WORLD|allowBackup|Log\.(d|i|w|e)" /tmp/jadx --include="*.java"
grep -rniE "NSAllowsArbitraryLoads|CFBundleURLSchemes|NSFileProtection|kSecAttrAccessible|WKScriptMessageHandler" /tmp/ipa/
```

## Attack Playbook (ordered)

1. **Decompile** and enumerate exported components, deep links, and URL schemes (PLATFORM).
2. **Static secret scan** (STORAGE/CRYPTO) — keys, tokens, hardcoded creds, backup exposure.
3. **Dynamic MITM** — bypass pinning, map the API surface, replay/inject (NETWORK).
4. **Deep-link + WebView injection** — parameter injection into bridge/redirect (PLATFORM/CODE).
5. **Auth flows** — biometric bypass, OAuth/PKCE, token storage (AUTH).
6. **Chain:** deep-link injection → WebView bridge → local file read/RCE; report as one chain with a `platform:` + `decompile_method:` + `deep_links:` block.
