# DoubleAgent 3.1.0 beta 4

## Changes

- Agent B separates Conversation, Notebook and Assessment into keyboard-accessible workspace tabs. The composer and pending questions remain available across views. Compact windows use a Controls drawer; Settings separates Connections, Skills and Run & scope.
- Connection states distinguish saved configuration from a successful check. Latest messages preserves manual transcript reading. Long replies expand in place, and draft messages survive task setup.
- The engagement notebook saves objectives, facts, questions, decisions and discussion history across restarts. Recent files can be reused and the notebook exported. Optional read-only Burp context grounds Discuss without assessment tools or target traffic; target changes require a new conversation.
- Both agents have explicit OpenRouter configuration. Agent B checks the key independently of the public model catalogue, then checks the exact model ID.
- Scope controls require a positive Burp decision before target execution, validate request destination/path agreement, reject model-supplied approvals and permission writes, and remove Agent B's direct curl fallback. Model-initiated Scanner delegation is disabled. Reload the updated Burp extension before assessment. See [scope controls](https://github.com/sageoffensive/DoubleAgent/blob/v3.1.0-beta.4/docs/agent-b-scope.md).
- Existing inline Review together/Review source, saved checks and separate consent for model sharing remain available.
- The displayed version is **v3.1.0-beta.4**; Mac bundle build **3104**.

## Human control and local data

Notebook facts are operator notes, not independently verified findings. Enabling Burp context and sending a Discuss message shares the bounded snapshot and notebook with the selected model connection. Notes remain local and unencrypted; redaction is best effort. New conversation clears engagement notes and discussion files, while separately saved source-review checks remain available.

Scope controls are not an operating-system sandbox or a firewall for manual traffic. A human approval cannot override excluded or unavailable Burp scope. Source review cannot execute code, send assessment target traffic or create findings; model sharing still requires its separate consent.

## Downloads

- `Agent-B-macOS-arm64-v3.1.0-beta.4.zip`: self-contained Apple Silicon app with bundled Python.
- `DoubleAgent-Burp-v3.1.0-beta.4.zip`: updated Agent A extension and modular source.
- `DoubleAgent-v3.1.0-beta.4.zip`: source and documentation for both agents.
- `SHA256SUMS`: archive checksums.

## Verification

- 187 Agent B tests and 29 extension tests passed. The exact app's bundled Python also passed all 187 Agent B tests.
- Jython compilation, exact-path guards, OpenRouter authentication/catalogue and the editable Swing model selector passed their offline smoke checks.
- JavaScript syntax and passive source-review offer checks passed.
- The signed app passed an isolated-runtime smoke check covering fresh settings, workspace/version UI, notebook persistence/export, uploads/downloads and source-review import/export.
- The packaged UI was checked for Notebook, inline source review, Settings tabs, always-on scope text and the displayed beta 4 version, with no browser console errors.
- Exact staged-source and app-bundle secret scans found no leaks. No settings, databases, model keys or uploaded evidence are included. Automated scanning does not guarantee detection of every possible secret.
- The Apple Silicon app is Developer ID-signed, Apple-notarized and stapled. Strict signature, stapled-ticket and Gatekeeper checks passed.

This remains a beta: clean-Mac quarantined installation, minimum-macOS compatibility, Intel support, live-provider responses and live-target behavior are not verified in this release workflow.
