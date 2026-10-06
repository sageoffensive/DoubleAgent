# DoubleAgent 3.1.0 beta 6

This release simplifies Agent B's chat and fixes duplicate-review recovery and failed Settings saves.

## Changes

- One chat with automatic routing. Conversation/Notebook/Assessment tabs, the mode selector, response-download buttons and the top status section are removed. Thinking and activity are collapsed by default. Pending questions appear once, with one reply box; approval choices remain explicit.
- Help is below Settings. Notes, context and exports remain in Settings → Run & scope. Existing consent-gated source review and offline JavaScript analysis are retained. Agent B uses its new black hat icon.
- **Load models** lists IDs from a connection's server without saving its draft or sending an inference request. Manual model entry remains available on catalogue failure; saved credentials cannot move silently to another server.
- Duplicate review retains an immutable comparison snapshot and accepted verdicts. Its read-only page tool recovers all rows after compaction and restart, including deleted duplicates. Changed populations, incomplete completion lists and unaccepted deletion receipts remain blocked. It cannot send target traffic or run scanners.
- Burp Settings validates the entire draft before applying any change. Invalid fields show a dialog and focus the field. Configuration writes are atomic; failed persistence restores the prior configuration, reporting PIN, provider keys and live state.
- Hidden FP counts and informational severity labels are clearer. Destructive finding actions require confirmation, and deletion retains selection identity if background rows change. Deleted duplicates remain deleted.
- Pending actions stay disabled across polling, stale connection-test results are ignored, cancelled password drafts are cleared, and waiting activity stops its timer. Saved verdict counts are labelled accurately.
- Displayed version **v3.1.0-beta.6**; Mac bundle build **3106**.

## Downloads

- `Agent-B-macOS-arm64-v3.1.0-beta.6.zip`: signed, notarized and stapled Apple Silicon app with bundled Python.
- `DoubleAgent-Burp-v3.1.0-beta.6.zip`: Burp extension and modular source. Reload the extension to activate its fixes.
- `DoubleAgent-v3.1.0-beta.6.zip`: reviewed source and documentation for both agents.
- `SHA256SUMS`: archive checksums.

## Verification and remaining limits

- 220 Agent B tests and 48 extension tests pass with the bundled Python 3.12 runtime. Regression checks force context compaction, recover every comparison ID, restore accepted deletion state after restart, deny unrelated calls, reject invalid settings without mutations, and restore files/live state after failed writes.
- JavaScript syntax, passive source-review checks and Burp Python compilation pass. Isolated UI checks cover the single chat, connection editor/catalogue controls, Help, notes under Settings, preserved source-review controls and narrow-window layout, with no browser errors.
- The exact app passes strict code-signature verification, Apple notarization, stapling, ticket validation and Gatekeeper. Its isolated runtime smoke test covers empty settings, startup/UI, notes/export, local upload/download, source import/export and offline JavaScript reports. No target traffic, scanner run or live finding/approval writes were used for these checks.
- Exact staged source and final app secret scans are clean. The shipped harness/UI matches reviewed source byte for byte, and release archives have published SHA-256 checksums.

This remains a **prerelease**. Validation was performed on Apple Silicon with macOS 27.2. A quarantined installation on a clean Mac, Intel and minimum-supported-macOS testing remain outstanding; the isolated smoke check does not substitute for these. The app targets Apple Silicon only. See [the macOS release checklist](macos-release.md).
