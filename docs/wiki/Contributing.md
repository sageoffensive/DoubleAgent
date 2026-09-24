# Contributing

Read the repository's `CONTRIBUTING.md`, `SECURITY.md`, and code of conduct before opening a pull request.

## Design principles

- Burp remains authoritative for scope, traffic, findings, and reporting.
- Model claims require authoritative read-back.
- Credentials belong to one connection and never cross providers.
- New conversations remain neutral until the operator explicitly loads Burp context.
- Deterministic safety and evidence gates take precedence over model convenience.
- Public defaults must not contain developer endpoints, paths, credentials, or target data.
- Keep `burp/DoubleAgent.py` as the single public Burp loader; implementation modules belong under `burp/src/`.

## Validation

```bash
node --check agent_b/static/app.js
python3 -m unittest discover -s tests -v
(cd agent_b && python3 -m unittest discover -s tests -v)
```

For macOS app changes, also build and verify the code signature.
