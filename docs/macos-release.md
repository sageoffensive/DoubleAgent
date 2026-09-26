# macOS release checklist

Agent B is an experimental harness. Do not present an ad-hoc or unnotarized
build as a frictionless public installer.

## Build and verify

Build on the architecture being distributed (Apple Silicon or Intel).
`agent_b/build-macos-app.sh` downloads pinned CPython 3.12.14, verifies its
SHA-256 digest, includes runtime licenses and signs nested code before the app.
An optional `PYTHON_RUNTIME_ARCHIVE` uses a cached archive with the same digest
check. No system Python installation is needed to run the app.

For local development:

```sh
cd agent_b
./build-macos-app.sh
"dist/Agent B.app/Contents/Resources/python/bin/python3" -E -s -B -m unittest discover -s tests -q
"dist/Agent B.app/Contents/Resources/python/bin/python3" -E -s -B tests/smoke_macos_bundle.py "dist/Agent B.app"
```

For distribution, list installed identities with `security find-identity -v -p codesigning`.
Create a notarization profile interactively with
`xcrun notarytool store-credentials "DoubleAgent"`. Enter credentials only in
the local prompt, never in a chat, repository, shell script or app bundle.
Then build using your own installed identity:

```sh
SIGN_IDENTITY="Developer ID Application: YOUR NAME (TEAMID)" \
NOTARIZE_KEYCHAIN_PROFILE="DoubleAgent" ./build-macos-app.sh
```

The notarizing build must pass strict signature verification, Apple submission,
stapling, ticket validation and Gatekeeper assessment. Old successful app
builds are preserved in `dist/previous-build.*`; inspect before removing them.
Signing/notarization credentials remain in the maintainer's Keychain. The
build rejects `MODEL_AUTH_FILE`; configure model keys in Settings after install.

Apple references: [notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)
and [resolving signing/notarization issues](https://developer.apple.com/documentation/security/resolving-common-notarization-issues).

## Test the exact release artifact

- Scan the exact staged source tree and packaged app with redacted secret-scan output.
- Ensure no model-auth file, settings, databases, uploaded files or assessment evidence are packaged.
- Archive the signed/stapled app with `ditto -c -k --keepParent` and publish a SHA-256 checksum.
- Download that archive in a browser on a fresh Mac without developer tools or Python.
- Move the app to Applications and open it without disabling Gatekeeper or removing quarantine.
- Confirm empty connection settings, startup, a harmless text upload/download, and normal quit/relaunch.
- Test on each advertised CPU architecture and supported macOS version; record what was actually tested.

The automated isolated-runtime smoke check is useful but does **not** replace
the quarantined clean-Mac UI installation test. Keep a release labelled beta
while this validation remains incomplete. Do not upload an app if notarization
rejects it; inspect Apple's log first.
