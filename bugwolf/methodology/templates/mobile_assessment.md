# Mobile Application Assessment

> iOS and Android app security assessment runbook.

_Template file: `mobile_assessment.md`_

## Scoping

- Receive IPA / APK from the developer. Confirm it's the latest production build.
- Identify the backend API: base URL, authentication scheme, certificate pinning.
- Document device targets: minimum OS version, tablet/phone, regional variants.
- Confirm jailbreak/root detection is in scope to test.
- Confirm anti-tampering (Frida, Magisk) is fair game.

## Static Analysis

- Decompile: jadx for Android, class-dump for iOS.
- Search for hardcoded secrets: API keys, AWS keys, signing keys.
- Search for insecure storage calls: SharedPreferences, NSUserDefaults, Keychain.
- Search for WebView and JS bridge usage: addJavascriptInterface, WKWebView.
- Search for export components: <intent-filter>, exported activities/services.

## Dynamic Analysis

- Set up Burp + mitmproxy on a jailbroken/rooted device.
- Bypass certificate pinning via Frida scripts (objection, ssl-pinning-bypass).
- Intercept and replay all API calls. Test IDOR, auth bypass, mass assignment.
- Capture all network traffic: look for PII leakage, debug logs.
- Fuzz all input fields: long strings, format strings, Unicode.

## Storage

- Inspect app data directory: databases, plists, key-value stores.
- Verify sensitive data encrypted at rest.
- Verify keychain entries use kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly.
- Check for backup eligibility: data extracted via iTunes/Firebase backup?

## Authentication

- Test biometric bypass: face ID with eyes closed, fingerprint with playback.
- Test session lifecycle: timeout on background, rotation on foreground.
- Test token storage: encrypted, scoped, refresh rotation.
- Test deep link hijacking: forged intents, unauthorized app-to-app launches.

## Reporting

- Findings mapped to OWASP MASVS / MASTG control IDs.
- Severity calibrated to device compromise and data sensitivity.
- Reproducer includes frida/objection snippets for dynamic bypass steps.

## Outputs

- `findings/*.yaml` — registered findings with severity and reproducer.
- `state/engagement/<id>/` — daily notes, surface map, evidence.
- `report/final.md` — final report delivered to the customer.
- `report/citations.md` — auto-generated methodology citations.

## Acceptance Criteria

- All findings reproducible from the documented evidence.
- Severity calibrated to the customer's business context.
- Every finding has at least one fix recommendation.
- Methodology citations attached via CitationEngine.
- Daily standups held; deviations from the runbook documented.
