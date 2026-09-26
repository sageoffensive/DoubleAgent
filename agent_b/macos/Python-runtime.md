# Bundled Python runtime

The macOS app includes CPython 3.12.14 from Astral's
[python-build-standalone release 20260924](https://github.com/astral-sh/python-build-standalone/releases/tag/20260924).
The build script pins each native architecture's archive URL and SHA-256 digest
and aborts if they do not match. No Python installation, Homebrew, or Xcode is
needed to run the resulting app. macOS 13 or later is required.

Runtime license texts and dependency notices remain in the bundled `python`
directory (including `lib/python3.12/LICENSE.txt` and package license
directories). The bundle retains pip's vendored certifi CA bundle and its license
for TLS verification; TLS verification is not disabled. User-installed Python
packages and PYTHON environment overrides are not loaded by the app launcher.

The runtime is signed inside-out with the same identity as the app. Signing is
not notarization. For public distribution, supply `SIGN_IDENTITY` and a saved
`NOTARIZE_KEYCHAIN_PROFILE`; the build must pass notarization, stapling and
Gatekeeper assessment. Also test the exact downloaded archive on a clean Mac.

Credentials are configured at runtime in Settings and must never be embedded
in a distributed bundle. `MODEL_AUTH_FILE` builds are rejected.
