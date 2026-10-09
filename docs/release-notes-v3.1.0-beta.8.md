# DoubleAgent 3.1.0 beta 8

Agent B now checks app access before Full App work and pauses credential-dependent work when authentication is uncertain. Double Agent's manual **Send to Repeater** action now uses the request attached to a finding instead of relying on Proxy history.

## App access before assessment

- Before Full App planning or model-driven testing, the harness reads captured Burp responses and checks the app's exact URL against Burp scope. A cookie or HTTP 200 alone does not prove authentication.
- When access or login is uncertain, choose **I'm signed in through Burp**, **The app doesn't need a login**, or **Stop**. Sign in through your Burp browser and confirm only once access works. Credential-dependent prompts omit the public-app choice.
- The question appears once, with context collapsed and the normal composer hidden. Passwords and tokens must not be pasted into chat. Only the displayed choices are accepted, and answers are single-use.
- Captured evidence and operator confirmation are labelled separately. The readiness check is passive: it sends no app request and neither source is presented as a fresh live login verification.
- A rejected session pauses for confirmation instead of automatically replaying authentication. Intentional anonymous control requests do not trigger a login prompt.
- Full App resume checks access again; readiness is not restored as permission from a checkpoint. Stop and app restart cancel pending questions. While waiting, the queue claim is kept alive; an incomplete check releases the claim where the local API is available.
- Regular chat, Connect to Burp, and read-only duplicate review do not require this gate. Burp's existing scope and safety decisions remain authoritative, with no override for uncertain or out-of-scope URLs.

## Repeater handoff repaired

- Findings **Send to Repeater** and double-click prefer the saved request, preserving its method, headers and body, even when the finding came from Scanner or Agent B rather than Proxy history.
- When no saved request exists, only an exact URL/method history match is used. A URL-only fallback creates a clearly labelled **URL starter** GET; it is not reported as the captured request or a verified PoC.
- Findings and queue buttons run Burp callbacks off Swing's event-dispatch thread. The selected finding or queue identity is captured before the worker starts, so sorting or a background refresh cannot select a different item.
- Queue URL-only handoffs preserve the URL path and query. Empty or unusable items report that no tab was created.
- Creating a Repeater tab does not send target traffic. The old browser-navigation fallback is removed.

## Downloads

- `Agent-B-macOS-arm64-v3.1.0-beta.8.zip`: signed, notarized and stapled Apple Silicon app, build **3108**, with bundled Python.
- `DoubleAgent-Burp-v3.1.0-beta.8.zip`: Burp loader and modular source. Extract the full archive and reload `burp/DoubleAgent.py` beside `burp/src/`.
- `DoubleAgent-v3.1.0-beta.8.zip`: reviewed source and documentation for both agents.
- `SHA256SUMS`: archive checksums.

## Verification and remaining limits

- 246 Agent B tests and 56 public-extension tests pass. Readiness regressions cover ambiguous cookies/200s, login forms, cross-origin and port mismatches, unavailable scope, explicit public access, rejected sessions, cancellation, restart, and gating before Full App planning.
- Repeater tests use callback stubs and synthetic requests, checking exact request preservation, sorted selection, history fallback, destination ports/TLS, URL paths/queries, and background-worker handoff. No live target traffic or scanner activity was used for this release verification.
- Jython 2.7.4 compilation and real Swing event-thread checks pass with stubbed Burp callbacks; CI repeats this compatibility check using a checksum-pinned Jython runtime.
- JavaScript checks, 246 tests against the bundled runtime, isolated startup/upload/download smoke checks, and exact source-to-bundle comparison pass. The Apple Silicon app is signed, notarized and stapled; strict signature and Gatekeeper checks pass. Source and packaged artifacts are scanned for secrets before publication.
- Live Burp Repeater callback verification remains outstanding. Automated smoke checks do not replace a quarantined clean-Mac installation test; Intel and minimum-supported-macOS validation remain outstanding. This is an experimental prerelease.
- The one-time internet permission controls from beta 7 remain in place. They govern supported public-reference retrieval, not configured model-provider traffic or every process on the host.
