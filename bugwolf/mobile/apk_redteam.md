# APK Red-Team Methodology

This document collects the steps a mobile-security auditor follows when
triaging an Android APK target.  The methodology is intentionally
broad — it covers static analysis, dynamic instrumentation, and
network-tier testing — and is structured around the OWASP MASVS v2.0
controls.

Each section begins with a one-line objective, follows with the
command-level procedure, and closes with an "audit checklist" the
auditor can paste into the engagement tracker.

---

## 1. Acquire & Verify

1. Pull the APK from a side-loaded source (Aptoide, APKMirror,
   direct vendor link).  Avoid the Play Store path because it
   produces a split-config APK that won't always match the on-device
   binary.
2. Verify the SHA-256 against the on-device binary via
   ``adb shell pm path com.target.app`` and ``adb pull``.
3. Capture the certificate (V1 / V2 / V3) with
   ``apktool d --use-aapt2`` and verify the signature chain.  A
   mismatch between the on-device cert and the shipped APK indicates
   a man-in-the-middle in the distribution path.

### Audit checklist
- [ ] SHA-256 of side-loaded APK matches on-device APK.
- [ ] Signature chain valid (apksigner verify --print-certs).

---

## 2. Static Decompilation

1. ``apktool d target.apk -o target/`` to produce a smali tree.
2. ``unzip -o target.apk -d target-raw/`` for the raw resource bundle.
3. Convert smali to Java with ``jadx`` (preferred) or
   ``d2j-dex2jar`` followed by ``cfr``.
4. Annotate every class with OWASP MASVS v2.0 control tags via the
   bugwolf pattern registry.

### Audit checklist
- [ ] All classes reviewed against MASVS-STORAGE, MASVS-AUTH,
   MASVS-CRYPTO, MASVS-NETWORK.
- [ ] Hard-coded URLs and API keys extracted to the engagement
   tracker.

---

## 3. Manifest Analysis

1. ``apkanalyzer manifest application-id target.apk``.
2. Inspect ``<application>`` for:
   - ``android:debuggable="true"`` (release build leak).
   - ``android:allowBackup="true"`` (auto-backup exposes app data
     via ``adb backup``).
   - ``android:usesCleartextTraffic="true"`` (enables HTTP).
   - Custom permissions with ``protectionLevel="normal"`` instead
     of ``signature``.
   - Exported ``<provider>``, ``<receiver>``, ``<service>``, and
     ``<activity>`` elements without ``android:permission``.
3. Inspect the network security config
   (``res/xml/network_security_config.xml``) for missing
   ``<base-config cleartextTrafficPermitted="true">`` settings.

### Audit checklist
- [ ] ``debuggable`` is ``false`` in release builds.
- [ ] All exported components have ``android:permission`` set.
- [ ] Cleartext is disabled at the application level.

---

## 4. Crypto Audit

1. ``frida -U -f com.target.app -l hook_crypto.js`` to dump keys.
2. Search the smali for ``Ljavax/crypto/Cipher;->getInstance`` calls
   and verify each uses a strong algorithm (AES/GCM/NoPadding,
   ChaCha20-Poly1305).  Anything else is a finding.
3. Verify no ECB mode.
4. Verify the IV is unique per encryption (not hardcoded).
5. Confirm the key source — keystore via ``AndroidKeyStore`` is the
   audit default.

### Audit checklist
- [ ] AES-GCM / ChaCha20-Poly1305 only.
- [ ] Keys sourced from ``AndroidKeyStore`` with ``setUserAuthenticationRequired(true)``
  where applicable.
- [ ] No raw ``KeyStore.getKey("alias", null)``.

---

## 5. SSL Pinning Bypass

1. ``objection -g com.target.app explore`` then
   ``android sslpinning disable``.
2. For custom pin sets, ``frida -U -l bypass_ssl.js``.
3. Re-validate with mitmproxy to confirm the bypass succeeded.
4. Document the bypass method in the report; this is not a finding
   per se but it enables network-tier testing.

### Audit checklist
- [ ] Pinning bypass reproducible with public scripts (no private
   exploit chain).
- [ ] mitmproxy captures HTTPS traffic without errors.

---

## 6. Native Code Analysis

1. Identify native libraries with
   ``unzip -l target.apk | grep "\.so$"``.
2. Run each .so through ``rabin2 -I lib.so`` to extract arch / metadata.
3. Use Ghidra / IDA / Binary Ninja to identify hardcoded crypto
   keys, hidden API endpoints, and ``strcpy`` / ``strcat`` /
   ``sprintf`` calls with attacker-controllable input.
4. Fuzz with ``afl++`` if the entry points are reachable.

### Audit checklist
- [ ] No hardcoded secrets in native libraries.
- [ ] Memory-corruption primitives called out separately.

---

## 7. Runtime Instrumentation

1. ``frida-server`` on the device.
2. ``frida -U -f com.target.app -l enumerate_classes.js`` to build
   the class map.
3. ``frida -U -l bypass_root.js`` to bypass root detection.
4. ``frida -U -l intercept_network.js`` to log outbound traffic.

### Audit checklist
- [ ] Root detection bypass documented.
- [ ] All network calls logged end-to-end.

---

## 8. Data-at-Rest Audit

1. ``adb shell run-as com.target.app ls -la /data/data/com.target.app/databases``.
2. Dump SQLite files via
   ``adb exec-out run-as com.target.app cat databases/app.db``.
3. Validate that sensitive fields are encrypted (column-level
   encryption or ``SQLCipher``).
4. Verify SharedPreferences use ``EncryptedSharedPreferences``
   rather than plaintext.

### Audit checklist
- [ ] PII columns encrypted.
- [ ] No plaintext credentials in SharedPreferences.

---

## 9. Reporting Tone

- Lead with the impact in dollars / records.
- Include a minimal reproduction script (Frida snippet preferred).
- Cite the MASVS control and CWE.
- Distinguish "we couldn't bypass X" from "X is secure".

---

## References

- OWASP MASVS v2.0
- OWASP MASTG v1.5
- bugwolf frida script catalog (`bugwolf/mobile/frida_scripts/`)