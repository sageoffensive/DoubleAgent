# Contributing to DoubleAgent

Thanks for helping improve DoubleAgent.

## Before you start

- Use the project only in authorized environments.
- Keep changes focused and avoid committing assessment data or credentials.
- Open an issue before a large architectural change so the approach can be discussed.

## Local checks

```bash
node --check agent_b/static/app.js
python3 -m unittest discover -s tests -v
(cd agent_b && python3 -m unittest discover -s tests -v)
```

For macOS app changes:

```bash
cd agent_b
./build-macos-app.sh
codesign --verify --deep --strict "dist/Agent B.app"
```

## Pull requests

Describe the operator-facing change, the security boundary it affects, and how it was tested. For UI changes, include a screenshot with test data only. For finding or traffic changes, explain how authoritative read-back and scope enforcement were verified.

Do not include API keys, tokens, cookies, real target URLs, customer data, local databases, or private assessment notes.
