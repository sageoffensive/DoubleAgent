# Installation

## Requirements

- Burp Suite Professional or Community
- Jython standalone 2.7.x configured in Burp
- Python 3.10 or later for Agent B
- macOS 13 or later for the optional native Agent B application
- One model connection that you configure

## Install the Burp extension

1. Download the latest `DoubleAgent-v3.0.0` release bundle.
2. Extract it to a stable folder.
3. Keep `double-agent-v3.0.py`, every `double_agent_*.py` module, `remote_reporting.py`, and `jev_duplicate_review.py` together.
4. In Burp, open **Extensions → Settings → Python Environment** and select the Jython standalone JAR.
5. Open **Extensions → Installed → Add**.
6. Choose **Python** and select `double-agent-v3.0.py`.
7. Confirm the **Double Agent** tab appears without an extension error.

If Burp's loader does not make the selected file's directory available to Jython, set `DOUBLE_AGENT_EXTENSION_DIR` to the extracted folder before launching Burp.

## Run Agent B from source

```bash
cd agent_b
./run.command
```

Open `http://127.0.0.1:4310`.

Agent B stores local state under `agent_b/data/`. The directory is ignored by Git and must not be shared.

## Build the macOS application

```bash
cd agent_b
./build-macos-app.sh
codesign --verify --deep --strict "dist/Agent B.app"
open "dist/Agent B.app"
```

The default build is ad-hoc signed. Maintainers can set `SIGN_IDENTITY` and `NOTARIZE_KEYCHAIN_PROFILE` for a distributable notarized build.

## Verify the services

Start the Agent API in Burp, then check:

```bash
curl -s http://127.0.0.1:8777/api/health
curl -s http://127.0.0.1:4310/api/health
```

Both should return JSON. Continue with [Configuration](Configuration).
