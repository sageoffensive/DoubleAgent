# DoubleAgent 3.1.0 beta 2 — human-directed research

Agent B now has a separate **Research** workspace in both the web harness and Mac app. Open it from the operator-chat header. The harnesses remain experimental works in progress; this is a prerelease, not a production-readiness claim.

## What's new

- Look up CVE, GHSA and OSV advisory records, including published affected ranges, withdrawal status and advisory/fix links.
- Preview exact dependency versions locally, then explicitly approve an OSV query. Supports pinned requirements, npm package-lock v2/v3 and flattened CycloneDX JSON with supported versioned package URLs.
- Retrieve 1–6 explicitly selected public GitHub source files at a resolved commit SHA, or import selected local UTF-8 source files. No repository cloning, installs, builds or code execution.
- Keep timestamped source/advisory evidence in a separate local notebook, with original file hashes, source links and Markdown export.
- Optionally ask the configured model to review one selected note for defensive concerns, uncertainty, questions and remediation. Sharing requires explicit consent for the displayed destination. The review has no tools and receives no assessment history or Burp credentials.
- Updated README and [research guide](https://github.com/sageoffensive/DoubleAgent/blob/v3.1.0-beta.2/docs/wiki/Research.md).

## Human control and limitations

Research never initiates target tests, creates assessment findings or automatically follows model suggestions. This feature is not autonomous vulnerability hunting, exploit retrieval or a general web browser. A version match or static concern is not proof of exploitability.

OSV/GitHub requests use verified HTTPS to fixed provider hosts, without inherited proxies, cookies or model credentials. Network lookup consent and model-sharing consent are separate. Cancelling cannot recall data already sent.

Notes are local but **not encrypted**. Secret redaction is best effort; inspect material before sharing. Limits are six source files of 120 KB each, 100 dependencies per query, 80,000 characters per model review and 100 notes / 16 MB per notebook. Unsupported entries and incomplete/paginated results are reported. OSV coverage is not exhaustive. Private GitHub authentication and whole-repository analysis are not included.

## Mac app and verification

- Apple Silicon, macOS 13 or later; bundled CPython 3.12.14, with no separate Python installation required.
- Developer ID-signed, Apple-notarized and stapled. Strict signature validation and Gatekeeper acceptance passed.
- 159 Agent B tests passed under the bundled Python runtime; 20 extension tests passed.
- Fresh-settings bundle smoke check passed: startup, empty connections/notebook, UI, harmless uploads/downloads and research import/export.
- Live public-data checks passed against OSV and GitHub. Browser checks covered advisory/dependency results, selected-file retrieval, consent reset, notebook reload and a 390-pixel layout without horizontal overflow.
- Exact staged-source, app-bundle and extracted-source-archive secret scans found no leaks. Automated scans cannot guarantee detection of every secret.
- No live target assessment or vulnerability reproduction was performed. AI review is fixture-tested, not live-provider verified. Clean-Mac quarantined installation, Intel support and the minimum supported macOS version were not tested here.

The standard first-launch confirmation for an internet-downloaded app may still appear. Do not disable Gatekeeper to work around validation failures.

## Downloads

- `Agent-B-macOS-arm64-v3.1.0-beta.2.zip` — signed and notarized Mac app.
- `DoubleAgent-Burp-v3.1.0-beta.2.zip` — Agent A Burp extension, unchanged in this release.
- `DoubleAgent-v3.1.0-beta.2.zip` — full source, both product halves and documentation.
- `SHA256SUMS` — checksums for all three archives.

Use only with software and systems you own or are authorised to review. Read the research guide before sharing private source with a hosted model.
