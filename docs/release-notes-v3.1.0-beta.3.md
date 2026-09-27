# DoubleAgent 3.1.0 beta 3 — a cleaner teammate experience

## Changes

- Read-only advisory/source checks now open inside chat. **Review together** offers can appear beneath replies mentioning a CVE or a possible version-related concern. **Review source** is also available beside the composer.
- The separate Research page is removed; old links return to chat. Existing local notes remain available under **Saved checks**.
- Connections and Skills move from the sidebar into separate Settings tabs. Run limits are under General. Tabs support keyboard navigation and preserve unsaved edits while switching.
- Shorter composer/footer copy and more concise Discuss/source-review prompts. File limits and privacy information are available on demand.
- The target link is removed from the chat header and remains in the sidebar.
- The running version is visible in chat and Settings. This build displays **v3.1.0-beta.3**; Mac bundle build **3103**.

## Human control

Offers are passive suggestions, not background scans or confirmed vulnerabilities. The human selects the package/advisory or exact source files and approves retrieval. Sharing a selected note with the configured model requires separate consent. Research cannot run code, send target traffic, create findings or automatically initiate assessment work. Assessment tools are unchanged.

Notes remain local, unencrypted and separate from chat history. Redaction is best effort. See the [source-review guide](https://github.com/sageoffensive/DoubleAgent/blob/v3.1.0-beta.3/docs/wiki/Research.md).

## Verification and Mac packaging

- 164 Agent B tests and 20 extension tests passed, plus JavaScript syntax and passive-offer checks.
- Bundled-runtime smoke check covers startup, fresh settings, visible version/tabs, uploads/downloads, source import/export and the legacy Research redirect.
- UI checks covered inline review, consent reset, Settings keyboard navigation, unsaved edits, Cancel, child-dialog return and validation of fields on hidden tabs.
- Developer ID-signed, Apple-notarized and stapled Apple Silicon app; signature, ticket and Gatekeeper checks passed.
- Exact staged-source and app-bundle secret scans found no leaks. Automated scans do not guarantee detection of every possible secret.

The harness remains a beta. Clean-Mac quarantined installation, minimum-macOS compatibility, Intel support and live-provider source-review responses are not verified. A standard first-launch confirmation may still appear. Do not disable Gatekeeper.

## Downloads

- `Agent-B-macOS-arm64-v3.1.0-beta.3.zip` — self-contained Mac app, with bundled Python.
- `DoubleAgent-Burp-v3.1.0-beta.3.zip` — Agent A Burp extension, unchanged in this release.
- `DoubleAgent-v3.1.0-beta.3.zip` — full source and documentation for both halves.
- `SHA256SUMS` — archive checksums.
