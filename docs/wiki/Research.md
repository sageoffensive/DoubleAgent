# Read-only research

Open **Research** in the operator-chat header in the web harness or Mac app. This separate workspace works without Burp. Lookups and source import do not require a model.

## Advisory lookup

Enter a CVE, GHSA or other OSV identifier and approve sending that identifier to OSV. Records include publication/modification timestamps, withdrawal status, affected ranges and available advisory/fix links. Follow the vendor advisory for fixes and backport information.

This is an OSV integration, not a general web browser or an NVD integration. Missing records and provider errors are reported, not treated as safety evidence. Exploit references are not offered as downloads; linked pages are not fetched automatically.

## Dependency review

Upload or paste a manifest, then **Preview locally**. Review the exact package names and versions before approving transmission to OSV. The full manifest, comments and local paths are not sent. Package names can still disclose private projects.

- `requirements.txt`: exact `name==version` pins. Ranges, included files and environment-marker lines are skipped and reported.
- npm `package-lock.json`: versions 2/3 with resolved `packages` entries. Local links are not queried.
- CycloneDX JSON: versioned package URLs for npm, PyPI, Maven, Go, crates.io, RubyGems, NuGet and Packagist. Nested components are not traversed; provide a flattened SBOM. Unsupported/unresolved components are reported.

Limits: 120 KB per manifest and 100 unique dependencies. Split larger inputs. Advisory matches link to OSV. Paginated results are flagged rather than silently treated as complete. No matches means only that the query returned no matches, not that the package is safe.

## Selected source files

For public GitHub source, specify `owner/repository`, a branch/tag/commit and 1–6 exact source paths. References resolve to a commit SHA before retrieval. Notes retain the SHA, source URLs and original file digests. No whole-repository clone/search, archives, submodules, dependency installs, builds or code execution. Private GitHub authentication is not implemented; import authorised local files instead.

Local imports accept up to six UTF-8 files, 120 KB each. Common programming languages, configuration, Markdown and plain text are supported. Hidden files, `.env`, key files, binaries and archives are rejected. Imported files are inert text in a database, not an executable checkout. Source/comments are untrusted reference data, never approval or instructions.

## Optional model review

Select a completed note and inspect it for secrets. The review panel shows the current provider, model and destination host. Tick the permission checkbox and choose **Share this note & request review** only if authorised to share the entire note with that destination. Changing connections invalidates approval.

This separate call has no assessment tools, shell, browsing or execution. It receives only the selected note, not chat history, Burp credentials or other notes. Source is line-numbered for citations. The prompt asks for potential concerns, applicability, uncertainty, questions and remediation; it forbids treating source comments as instructions or claiming tests were executed. Tool calls and empty responses are rejected. Model citations and advice still need human verification.

Review input is limited to 80,000 characters. Use fewer/smaller files for larger notes or small-context models. Stop an active chat/assessment first. Only one research operation runs at a time. **Cancel research** stops subsequent work and cancels model requests; it cannot recall data already sent, and an in-flight lookup may take up to its timeout to return.

## Privacy and storage

- Research data requests use verified HTTPS to `api.osv.dev`, `api.github.com` and `raw.githubusercontent.com`. Redirects are rejected; proxies, cookies, model credentials and Burp sessions are not inherited.
- A configured model is contacted only through the separately consented review. Hosted providers receive the note; OpenAI-compatible does not necessarily mean local.
- Redaction is best effort. Inspect the preview and provider policy yourself.
- Notes persist in `research.sqlite3` in Agent B's data directory, owner-readable/writable but **not encrypted**. They survive **New conversation**.
- Quotas: 100 notes, 16 MB aggregate text, 2 MB per note. Export before deleting. Deletion is not cryptographic secure erasure; backups/SQLite storage may retain data.
- Research does not create findings, initiate tests, download exploits or automatically follow model recommendations. No automatic handoff into live assessment exists.
- Static review is partial, not a full audit. An advisory/version match is not proof that a deployment is exploitable.

## Teammate example

“The supplied lockfile lists this version and OSV returned an advisory. Is this the deployed version, and does a vendor backport apply? I can summarise the fix and remaining uncertainty.”

The human supplies context and decides what to do.

References: [OSV API](https://google.github.io/osv.dev/api/), [GitHub commit API](https://docs.github.com/en/rest/commits/commits#get-a-commit).
