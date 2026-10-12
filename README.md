# DoubleAgent

AI-assisted web security testing through Burp Suite. Agent A handles traffic and evidence; Agent B is an optional chat harness for your chosen model.

## Choose your component

| Folder | What it contains | Start here |
| --- | --- | --- |
| [agent_A_burp](agent_A_burp/) | Agent A: the Burp extension | Load `DoubleAgent.py` in Burp |
| [agent_b_mac](agent_b_mac/) | Agent B: the ready-to-run Mac app | [Download the app ZIP](https://github.com/sageoffensive/DoubleAgent/raw/refs/heads/main/agent_b_mac/Agent-B-macOS-arm64-v3.1.0-beta.8.zip) |
| [agent_b_web](agent_b_web/) | Agent B: source and local web interface | Run `./run.command` with Python 3.10+ |

The Mac and web interfaces use the same Agent B harness. Choose whichever suits you. Agent B remains experimental; the current app is **v3.1.0-beta.8**, signed and notarized for **Apple Silicon, macOS 13+**. See the [release notes](https://github.com/sageoffensive/DoubleAgent/releases/tag/v3.1.0-beta.8) for validation limits.

## Get started

1. Download or clone this repository. In Burp, configure Jython standalone 2.7.x under **Extensions → Settings → Python Environment**.
2. Add a **Python** extension and select **`agent_A_burp/DoubleAgent.py`**. Keep its `src` folder beside it.
3. Set your target and scope in Burp, then start Agent A's local API on `127.0.0.1:8777`.
4. Open the Mac app, or run the web version:

   ```sh
   cd agent_b_web
   ./run.command
   ```

   For the web version, open `http://127.0.0.1:4310`.
5. In Agent B, add your model under **Settings → Connections**, then select **Connect to Burp**.

For Mac installation, extract the ZIP from `agent_b_mac` and move **Agent B.app** to Applications. No separate Python installation is needed. The Mac folder contains only the packaged app; its build source lives in `agent_b_web/macos`.

You can also use Agent A with Codex or Claude Code: paste Agent A's generated activation prompt into a fresh session. Agent B is optional.

## Let your agent set it up

Copy **one** prompt into your coding agent. It will do the local setup and guide you through any Burp steps it cannot perform.

<details>
<summary><strong>Mac app + Burp — easiest on Apple Silicon</strong></summary>

```text
Set up DoubleAgent for me: https://github.com/sageoffensive/DoubleAgent
First ask me where to keep the DoubleAgent/Burp files and where to install
Agent B.app (suggest /Applications or ~/Applications). Wait for my answer
before downloading, cloning or moving files. If you find an existing
checkout, offer to reuse it and confirm that choice with me. Use my chosen
locations, then read the current README and installation instructions.
Check this Mac meets the published app requirements. Use the ready-built ZIP in agent_b_mac; verify
it against the matching release's SHA256SUMS, extract it and install Agent B
in my chosen app folder. Preserve existing apps, settings and conversations;
don't replace or restart an active instance. Keep Gatekeeper enabled.

Check Burp and Jython, then help me load agent_A_burp/DoubleAgent.py with
its src folder intact. Start Agent A's API on loopback and open Agent B.
Guide me through Settings → Connections and Connect to Burp. Have me enter
any keys directly in Settings, never in chat or committed files. Use my
existing model server; don't install or restart one. Verify local service
health, report anything still needing my input, and stop before assessment.
```

</details>

<details>
<summary><strong>Web interface + Burp</strong></summary>

```text
Set up DoubleAgent's local web interface for me:
https://github.com/sageoffensive/DoubleAgent
First ask me which folder I want DoubleAgent installed in. Wait for my
answer before downloading, cloning or moving files. If you find an existing
checkout, offer to reuse it and confirm that choice with me. Use the folder
I choose, then read the current README and installation instructions.
Check Python 3.10+, Burp and Jython, then help me load agent_A_burp/DoubleAgent.py with its src
folder intact and start Agent A's loopback API.

From agent_b_web, use a supported Python to run:
python3 -B -m agent_b_harness.server
Reuse a healthy existing instance instead of starting another. Keep the
listener on loopback and open http://127.0.0.1:4310. Guide me through
Settings → Connections and Connect to Burp. Have me enter keys directly
in Settings, never in chat or committed files. Preserve existing settings
and conversations. Use my existing model server; don't install or restart
one. Verify local service health and stop before assessment.
```

</details>

<details>
<summary><strong>Just Agent A — use my existing coding agent</strong></summary>

```text
Help me set up the Burp extension from:
https://github.com/sageoffensive/DoubleAgent
First ask me which folder I want DoubleAgent installed in. Wait for my
answer before downloading, cloning or moving files. If you find an existing
checkout, offer to reuse it and confirm that choice with me. Use the folder
I choose, then read the current README and installation instructions.
Check Burp and Jython, then help me load agent_A_burp/DoubleAgent.py with its src folder intact
and start Agent A's API on 127.0.0.1:8777. Verify local service health.

I want to use my existing coding agent, so don't install or start Agent B.
Guide me to Agent A's generated activation prompt and have me paste it
into a fresh agent session. Use that live operating contract rather than
inventing tool instructions. Don't request credentials in chat, change
my target scope, or send target traffic during setup. Report readiness
and any remaining manual steps; wait for my assessment instructions.
```

</details>

## Why use Agent B?

Agent B gives the model a limited toolset and checks target actions against Burp's exact URL scope before dispatch. Outside or unavailable scope is blocked. Supported internet reference lookups require a one-time **Allow / Deny** decision showing the destination, data and reason. Full App assessments check app access first and pause when authentication is uncertain.

These controls help reduce scope creep and unsafe model actions. Configured model-provider calls have separate controls; this is not a host firewall or a sandbox for other applications. General-purpose harnesses retain their own shell and network permissions. [Compare harnesses](docs/harness-comparison.md).

Both agents support local/OpenAI-compatible model servers. Agent B also supports OpenAI, OpenRouter, Anthropic and Bedrock, with credentials kept per connection.

## More information

- [Installation](docs/wiki/Installation.md) · [Configuration](docs/wiki/Configuration.md) · [Troubleshooting](docs/wiki/Troubleshooting.md)
- [Agent B controls](agent_b_web/README.md#scope-enforcement) · [Internet permissions](docs/wiki/Research.md)
- [Contributing and checks](CONTRIBUTING.md) · [Releases and checksums](https://github.com/sageoffensive/DoubleAgent/releases)

Use only on systems you own or are explicitly authorized to test. [MIT license](LICENSE).
