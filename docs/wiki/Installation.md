# Installation

DoubleAgent has two required halves: **Agent A in Burp** and **Agent B in a browser or macOS app**.

## What you need

- Burp Suite Professional or Community
- Jython standalone 2.7.x
- PortSwigger's MCP Server BApp for full Burp-native capability
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

## Step 2: enable PortSwigger MCP

1. In Burp, open **Extensions → BApp Store**.
2. Install **MCP Server** by PortSwigger.
3. Open Burp's **MCP** tab and enable the server.
4. Keep the listener on `127.0.0.1:9876` unless you have a local port conflict.

Agent B uses MCP indirectly: Agent B requests an action from Agent A, Agent A applies scope and safety gates, and only then does Agent A call the local MCP server. You do not need to configure Claude Desktop or the MCP stdio proxy.

Read [PortSwigger MCP integration](PortSwigger-MCP.md) for the architecture, verification commands, fallbacks and security settings.

## Step 3A: start Agent B in a browser

From the extracted source:

```bash
cd agent_b
./run.command
```

Open [http://127.0.0.1:4310](http://127.0.0.1:4310).

Agent B uses the Python standard library and starts with no saved model connection. Its local state lives under `agent_b/data/`, which is ignored by Git and should never be shared.

## Step 3B: install Agent B on macOS

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

## Step 4: verify the local services

With Agent A's API and Agent B running:

```bash
curl -s http://127.0.0.1:8777/api/health
curl -s http://127.0.0.1:4310/api/health
curl --max-time 2 -N -i http://127.0.0.1:9876/
```

The Agent A and Agent B health checks should return JSON. The MCP request should return an event-stream response containing an `endpoint` event; its short timeout is expected.

## Step 5: connect the team

1. Add and test a model under **Agent B → Settings → Add connection**.
2. Set the authorized target scope in Burp.
3. Select **Send bootstrap** in Agent B.
4. Review the target and scope Agent B received.

Continue with [Configuration](Configuration.md) or [Operator Workflows](Operator-Workflows.md).
