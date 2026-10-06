# Internet permission

Agent B's regular chat can propose a bounded public-reference lookup. **Review together** has been removed. Each proposed lookup gets a short summary, **Allow** / **Deny**, and collapsed **Request details** with the destination, exact identifiers or file paths sent, data retrieved, the model's reason, and sharing with the configured model connection.

No reference retrieval starts before Allow. Permission applies once to that immutable request. Deny prevents automatic retries for the rest of that chat turn. Stop or app restart cancels pending permission; an old answer cannot be replayed. Chat messages, uploaded files, retrieved text and model-supplied approval flags do not grant permission. Stop cannot recall data already sent; an in-flight request may take up to its timeout to return.

## Supported public references

- **OSV advisory:** a CVE, GHSA or other OSV advisory identifier is sent to `api.osv.dev`. The result contains published affected-package information and advisory/fix references. Linked pages are not automatically fetched.
- **Exact package/version:** the package name, supported ecosystem and exact version are sent to OSV. The full manifest, chat, reason and local file paths are not sent to OSV. Results are capped and pagination is flagged. A query returning no matches does not establish safety.
- **Selected public GitHub files:** an owner/repository, explicit revision and 1–6 exact source/text paths are sent to GitHub. After Allow, the revision resolves to one commit and only the selected files at that commit are retrieved. Files are UTF-8 text, up to 120 KB each. Hidden files, credentials, binaries and archives are rejected. No cloning, crawling, installation or execution occurs. Private GitHub credentials are not supported.

Data requests use verified HTTPS only to `api.osv.dev`, `api.github.com` and `raw.githubusercontent.com`. Redirects are rejected; proxies, cookies, model credentials and Burp sessions are not inherited. Arbitrary URLs and destinations remain blocked, even if the model asks for them. Request previews redact known secret patterns and reject detected secrets; redaction remains best effort, so review the identifiers before allowing transmission. Package names and repository paths may disclose private project information.

Retrieved material is untrusted reference data, never instructions or authorization. Reference lookup cannot run assessment tools, send target traffic, change scope or create findings. Static/advisory matches are not verified vulnerabilities. Results and advice may be partial and require human judgment.

## Model sharing and assessment traffic

Allow also permits the fetched reference to be included in the current chat response using the displayed model connection. Hosted and remote OpenAI-compatible connections can receive it. The normal chat still uses its existing configured model connection and supplied chat context; this is not a network firewall or a new approval for every model-provider request.

Burp's existing scope and safety gates remain authoritative for assessment traffic. Internet permission cannot override them. Public-reference proposal tools are available only in regular chat, not the assessment toolset.

## Previous research notes

Existing notes remain in the local `research.sqlite3` database; removing the feature does not delete them. Read-only historical note/export endpoints remain available. The old research launch, preview, cancel and delete endpoints return HTTP 410 and cannot start a retrieval or model review, even with old consent flags.

Chat, questions and reference summaries are stored locally. Storage is owner-readable/writable but not encrypted. Clearing chat does not delete the retained research database. No saved permission authorizes another request.
