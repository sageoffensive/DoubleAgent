# Bundled Markdown dependencies

Marked 18.1.1 (MIT) and DOMPurify 3.4.17 (MPL-2.0 or Apache-2.0) are vendored from their npm release tarballs. Tarball SHA-512 integrity and file SHA-256 values are recorded in manifest.json. License files accompany each library. The app loads these local files; it does not use a CDN at runtime.

Upstream: https://marked.js.org/ and https://github.com/cure53/DOMPurify. Keep both current and re-run the chat rendering and malicious Markdown checks when updating.
