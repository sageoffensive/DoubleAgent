
---
name: analyze-js
description: Analyze JavaScript files for API endpoints, secrets, URLs, emails, sensitive files, and bundler versions
examples:
  - analyze-js bundle.js
  - analyze-js src/
  - analyze-js --verbose dist/
---

# JS Analyzer Skill

Analyzes JavaScript files for security-relevant information using `npx js-analyzer-cli`.
Works in any project without installation.

## Command

```bash
npx js-analyzer-cli [OPTIONS] <paths...>
```

## Detection Categories

- **endpoints**: REST APIs, GraphQL, OAuth, admin panels
- **urls**: External links, cloud storage, WebSockets
- **secrets**: API keys, tokens, JWT, credentials (auto-masked)
- **emails**: Valid addresses (test emails filtered)
- **files**: Sensitive file references (.env, configs, backups)
- **bundlers**: Detected bundlers with versions (Webpack, Vite, Rollup, etc.)

Auto-filters noise: build artifacts, module imports, XML namespaces.

## Options

- `--verbose` - Show progress details
- `--format=json` - JSON output (default: toon)
- `--pretty` - Pretty print JSON
- `--no-recursive` - Skip subdirectories

## Directory Scanning

Default behavior:
- Finds `.js`, `.jsx`, `.mjs` files
- Skips `node_modules/` and hidden dirs
- Recursive by default

## Output Format

TOON format (default) - compact, LLM-optimized:
```
summary:
  total: 18
  endpoints: 4
  secrets: 1
findings:
  endpoints[4	]{value	location}:
    /api/v1/users	bundle.js:42:15
    /admin/dashboard	bundle.js:234:12
  secrets[1	]{value	location}:
    AKIA...MPLE (AWS Key)	bundle.js:312:25
```

Location format: `file:line:column` (clickable in IDEs)

## How to Present Results

Start with summary, highlight critical findings (secrets, admin endpoints), group by category.

Example:
```
📊 Analysis: bundle.js (18 findings)

🔴 Critical:
• AWS Key at bundle.js:312:25
• Admin endpoint at bundle.js:234:12

Endpoints (4): /api/v1/users (bundle.js:42:15), /admin/dashboard (bundle.js:234:12), ...
Bundler: Webpack 5.88.2
```

## Usage Flow

1. Identify paths
2. Add flags if needed
3. Run: `npx js-analyzer-cli [flags] <paths>`
4. Parse and present

Note: First run downloads package (~2s), then cached.

## Security

For authorized testing only: pentesting, bug bounties, own applications, security audits.
