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

## APK triage pipeline (ordered automation sequence)

The sections above are what to look for; this is the concrete order to run
it in on a fresh APK, decompile through instrumentation, so nothing gets
skipped because it "wasn't the next obvious step."

1. **Decompile.** `jadx -d decompiled_<pkg>/ <pkg>.apk` for a readable
   source tree; fall back to `apktool d <pkg>.apk -o decoded_<pkg>/` when
   you need the binary `AndroidManifest.xml` decoded rather than jadx's
   resource-folder copy. For a large APK where full decompilation is slow
   or OOMs, run a strings-only first pass:
   `find <pkg>_extracted -name "classes*.dex" -exec strings -8 {} \; > strings_<pkg>.txt`.
   Don't stop at `classes.dex` -- multi-dex APKs keep secrets in
   `classes2.dex` onward, and a `.xapk` needs its split APKs (`base.apk`,
   `config.*.apk`) unzipped and decompiled individually first.

2. **Static secret scan.** Grep the decompiled tree / strings dump for
   high-signal patterns, not generic words like "password" -- specific
   prefixes are far lower-noise: `AKIA[A-Z0-9]{16}` (AWS key),
   `AIza[A-Za-z0-9_-]{35}` (Google API key), `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`
   (JWT), `gh[ps]_[A-Za-z0-9]{36}` (GitHub PAT), `sk_live_[A-Za-z0-9]{24}`
   (Stripe). Also grep for the target's own domains in embedded URLs
   (internal API hosts not seen in passive recon), and check
   `google-services.json` / `strings.xml` for Firebase `project_id`,
   `storage_bucket`, and `api_key` -- each is worth testing directly for
   public Firestore/RTDB/Storage read once found.

3. **Manifest analysis.** From the decoded manifest, enumerate
   `<activity>`, `<service>`, `<receiver>`, and `<provider>` entries and
   filter to `android:exported="true"` (explicit or implicit via an
   intent-filter). For each exported component, check whether it accepts
   extras that reach a WebView (intent -> WebView -> XSS/`file://`), a URI
   extra (deep-link SSRF), or extras forwarded into another Activity
   (intent redirection). Also pull any pinned certs from `assets/`
   (`*.cer`/`*.der`/`*.pem`) or `network_security_config.xml` -- the
   cert's Subject/SAN can reveal an internal API host that never surfaced
   in recon.

4. **Dynamic instrumentation.** Only once static triage is exhausted: spin
   up Frida (`frida -U -l pinning-bypass.js -f <pkg> --no-pause`) to
   bypass OkHttp/`TrustManagerImpl` certificate pinning, then route
   traffic through an intercepting proxy to capture the live API surface
   and confirm which static-scan findings (tokens, endpoints, Firebase
   config) are actually still active server-side rather than dead build
   artifacts. Use objection (`objection --gadget <pkg> explore`) for quick
   method-level arg/return dumps when a specific class is the target
   rather than full traffic capture. Run this stage against a rooted
   emulator or dedicated test device only, never a production device.

Treat an expired JWT or a dead-looking endpoint from stage 2 as intel, not
a dead end -- the path structure and signing algorithm carried into stage
4 are still useful even when the token itself no longer authenticates.
