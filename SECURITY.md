# Security policy

## Supported version

Security fixes target the latest published release of DoubleAgent.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability in DoubleAgent.

Use GitHub's private vulnerability reporting feature for this repository. Include:

- the affected version or commit;
- a concise impact statement;
- reproduction steps or a minimal proof of concept;
- any relevant logs with tokens, API keys, cookies, target data, and personal data removed.

You should receive an acknowledgement within seven days. Please allow time for validation and a coordinated fix before public disclosure.

## Operational security

- Use DoubleAgent only on systems you own or are explicitly authorized to test.
- Keep the API bound to loopback unless you have added an authenticated, trusted transport boundary.
- Never commit `creds.md`, `double-agent.json`, Agent B's `data/` directory, model auth files, or assessment evidence.
- Treat model output and imported methodology as untrusted input.
- Review every state-changing or potentially disruptive test before execution.
