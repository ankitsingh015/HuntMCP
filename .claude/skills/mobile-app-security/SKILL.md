---
name: mobile-app-security
description: Mobile app (APK/IPA) testing checklist mapped to OWASP MASVS -- static decompilation for hardcoded secrets, Frida/objection cert-pinning bypass, deep-link and WebView JS-bridge hijacking, exported-component IPC abuse, backup/keystore extraction, root/frida detection bypass, biometric fallback abuse, and React Native/Flutter bundle extraction. Converted from master-pentest-prompt.md Phase 34. Use only when an APK or IPA is explicitly in scope.
---

# Mobile app deep dive (APK/IPA in scope) -- OWASP MASVS

## When to use

Only when an APK or IPA is explicitly listed in scope -- this is a
distinct skill set from web/API testing and assumes the binary itself
is available to analyze.

## Static analysis

Decompile the APK with `jadx` (or the IPA with Hopper + `class-dump`)
and grep the output for hardcoded API keys, secrets, embedded endpoint
URLs, and any self-signed-CA certificate-pinning bypass code already
built into the app (a sign the pinning is weaker than it looks).

## Dynamic analysis

Frida/objection to bypass certificate pinning across OkHttp,
NSURLSession, and native hooking implementations; force cleartext HTTP
where the app tries to prevent it; MITM the full session once pinning
is bypassed.

## Deep links

Map the app's URL scheme handler -- a deep-link hijack chained through a
crafted parameter can reach a WebView and from there make unauthenticated
calls to backend APIs the WebView itself is authenticated for.

## WebView

An exposed JS bridge (`addJavascriptInterface` on Android is the classic
RCE vector), `file://` access from within the WebView, mixed content
loading, and missing origin checks on `postMessage`-style bridges.

## IPC (Android)

Exported components/activities/providers (`android:exported="true"`),
intent injection, and content-provider access (read-database exposure,
seed-phrase/credential theft via a provider that shouldn't be reachable)
via intents sent from other apps or system components.

## Backup & local storage

ADB backup extraction, SharedPreferences/SQLite files, Keystore/
`sqlcipher` handling, clipboard content leaking after a copy action, and
screen-pinning bypass.

## Anti-tampering bypass

Root/emulator/Frida-detection bypass, revealing hidden device IDs
through a bypassed face/root check.

## Biometric auth

Check whether biometric authentication has a fallback path to a device
PIN/passcode that reintroduces a weaker auth factor than the biometric
gate implied.

## React Native / Flutter

Extract the JS bundle (React Native) and check for JS-bridge misuse; for
Flutter, check how secure storage is actually implemented under the
hood rather than trusting the plugin name.

## Store-side checks

Test the actual version distributed on the app store -- a build can be
signed off in review with different behavior than what ships; also check
for an accidentally-uploaded debug build alongside the release build.
