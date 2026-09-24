# Installation

DoubleAgent has two required halves: **Agent A in Burp** and **Agent B in a browser or macOS app**.

## What you need

- Burp Suite Professional or Community
- Jython standalone 2.7.x
- Python 3.10 or later when running Agent B from source
- macOS 13 or later for the optional Agent B application
- A model connection you configure yourself

## Step 1: install Agent A

1. Download and extract the latest `DoubleAgent-v3.0.1.zip` release bundle.
2. In Burp, open **Extensions → Settings → Python Environment**.
3. Select your Jython standalone JAR.
4. Open **Extensions → Installed → Add**.
5. Choose **Python** and select:

   ```text
   burp/DoubleAgent.py
   ```

6. Confirm the **Double Agent** tab appears without an extension error.
7. Open the **Agent AI** tab and start the Agent API.

`DoubleAgent.py` automatically finds `burp/src/`. You do not need to select or move any of the internal files.

If an unusual launcher cannot locate the source folder, set `DOUBLE_AGENT_EXTENSION_DIR` to the extracted `burp` folder before starting Burp.

## Step 2A: start Agent B in a browser

From the extracted source:

```bash
cd agent_b
./run.command
```

Open [http://127.0.0.1:4310](http://127.0.0.1:4310).

Agent B uses the Python standard library and starts with no saved model connection. Its local state lives under `agent_b/data/`, which is ignored by Git and should never be shared.

## Step 2B: install Agent B on macOS

Instead of the browser launch above:

1. Download `Agent-B-macOS-v3.0.1.zip` from the latest release.
2. Extract **Agent B.app**.
3. Move it to **Applications**.
4. Open the app.

Developers can build it locally:

```bash
cd agent_b
./build-macos-app.sh
codesign --verify --deep --strict "dist/Agent B.app"
open "dist/Agent B.app"
```

## Step 3: verify both halves

With Agent A's API and Agent B running:

```bash
curl -s http://127.0.0.1:8777/api/health
curl -s http://127.0.0.1:4310/api/health
```

Both commands should return JSON.

## Step 4: connect the team

1. Add and test a model under **Agent B → Settings → Add connection**.
2. Set the authorized target scope in Burp.
3. Select **Send bootstrap** in Agent B.
4. Review the target and scope Agent B received.

Continue with [Configuration](Configuration.md) or [Operator Workflows](Operator-Workflows.md).
