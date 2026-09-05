# iOS Red-Team Methodology

This document captures the canonical iOS app audit methodology.  It is
structured around the OWASP MASVS v2.0 controls, the iOS Application
Security Testing Guide (MASTG), and the practical workflow used by
public bounty hunters.  The methodology is intentionally repeatable:
every step has a one-line command an operator can paste.

---

## 1. Acquire the IPA

1. Pull from the App Store via ``frida-ios-dump`` (requires a
   jailbroken device).
2. Alternative: install via App Store, then ``frida -H <host>
   -p`` and ``--codesign`` from a jailbroken device.
3. Alternative: pull from a CI artifact (TestFlight / Diawi).

Verify the SHA-256 against the on-device binary:

```
adb shell sha256sum /var/containers/Bundle/Application/<UUID>/Target.app/Target
```

### Audit checklist
- [ ] IPA SHA-256 matches on-device binary.
- [ ] Codesigning identity matches Apple's developer profile.

---

## 2. Decompilation

1. ``unzip -o target.ipa -d target/``.
2. Use ``otool -L Target.app/Target`` to list linked libraries.
3. Run ``class-dump`` (jtool / ktool alternatives) to produce
   Objective-C headers.
4. Run ``swift-demangle`` on the binary to recover Swift symbols.

### Audit checklist
- [ ] All exported Objective-C classes dumped.
- [ ] All Swift symbols demangled and reviewed.

---

## 3. Binary Inspection

1. ``otool -l Target.app/Target | grep -A4 cryptid`` to confirm
   AppStore encryption (``cryptid == 1``).
3. For jailbroken-target binaries: ``otool -l`` shows
   ``__RESTRICT`` segment; absence indicates dyld bypass.
4. ``strings Target.app/Target | grep -iE "https?://|apikey|password"``
   to surface hardcoded credentials.
5. Run ``rabin2 -I Target.app/Target`` to extract linked framework
   versions.

### Audit checklist
- [ ] No hardcoded credentials.
- [ ] Linked libraries match Apple's published list.

---

## 4. Storage Audit

1. On a jailbroken device:
   ```
   ssh root@iphone "find /var/mobile/Containers/Data/Application -name '*'"
   ```
2. Inspect the Documents, Library, Caches directories.
3. Verify the app uses ``Data Protection Class = Complete``
   (``NSFileProtectionComplete``).
4. Validate SQLite files via ``sqlite3`` and verify no PII is in
   plaintext.
5. Inspect the Keychain with ``dump_keychain.js`` (Frida).

### Audit checklist
- [ ] Sensitive files use ``NSFileProtectionComplete``.
- [ ] Keychain entries use ``kSecAttrAccessibleWhenUnlockedThisDeviceOnly``.

---

## 5. Network Audit

1. ``frida -U -f com.target.app -l bypass_ssl.js`` to install
   custom trust manager.
2. Start mitmproxy; verify HTTPS intercept.
3. Verify ATS (App Transport Security) is enforced:
   ```
   /usr/libexec/PlistBuddy -c "Print :NSAppTransportSecurity" Target.app/Info.plist
   ```
4. Look for ``NSAllowsArbitraryLoads == true`` (finding).
5. Look for ``NSAllowsLocalNetworking == true`` (informational).

### Audit checklist
- [ ] ATS enforced.
- [ ] No arbitrary loads.

---

## 6. Jailbreak Detection Bypass

1. ``frida -U -f com.target.app -l bypass_jailbreak.js``.
2. Re-validate the app's behaviour against the post-bypass state.
3. Document the bypass surface; report jailbreak detection as
   medium-severity if it is the only line of defence.

### Audit checklist
- [ ] Bypass reproducible.
- [ ] Detection does not protect sensitive flow without second factor.

---

## 7. Crypto Audit

1. Use ``frida -U -l hook_crypto.js`` to hook ``CCCrypt`` and
   ``SecKeyCreateEncryptedData``.
2. Verify the cipher suite is AES-GCM / ChaCha20-Poly1305.
3. Verify the IV is per-message (not hardcoded).
4. Verify the key source — Keychain (with biometric ACL) is the
   audit default.

### Audit checklist
- [ ] AES-GCM / ChaCha20-Poly1305 only.
- [ ] Keychain entry protected with ``kSecAttrAccessControl``.

---

## 8. URL Handler Abuse

1. Inspect ``CFBundleURLTypes`` in Info.plist:
   ```
   /usr/libexec/PlistBuddy -c "Print :CFBundleURLTypes" Target.app/Info.plist
   ```
2. Look for ``CFBundleURLSchemes`` like ``target://`` that accept
   arbitrary paths; these can be abused via Safari's universal
   links.
3. Verify the ``application:openURL:options:`` method validates
   source application and URL pattern.

### Audit checklist
- [ ] URL handlers validate source application.
- [ ] No wildcard path matching.

---

## 9. Universal Links

1. Fetch ``https://<domain>/apple-app-site-association``.
2. Verify the JSON lists the app's bundle ID and only the
   intended paths.
3. Test for path-confusion: ``/path1/path2`` should not match
   ``/path1`` if the JSON says only ``/path1``.

### Audit checklist
- [ ] AASA file lists exact paths.
- [ ] No wildcard at the path root.

---

## 10. Reporting

- Lead with impact.
- Cite MASVS / MASTG / CWE.
- Provide a Frida snippet for the bypass.
- Distinguish "no bypass found" from "secure".

---

## References

- OWASP MASVS v2.0
- OWASP MASTG v1.5
- Apple Platform Security Guide (latest)
- bugwolf frida script catalog