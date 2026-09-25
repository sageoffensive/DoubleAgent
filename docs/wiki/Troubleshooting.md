# Troubleshooting

## Burp cannot load the extension

- Confirm Jython standalone is configured.
- Keep `burp/DoubleAgent.py` beside the `burp/src/` folder.
- Load `burp/DoubleAgent.py`, not a file under `burp/src/`.
- Set `DOUBLE_AGENT_EXTENSION_DIR` to `burp/` if an unusual launcher does not expose the selected file's directory.
- Check Burp's extension output for the first import error.

## Agent B cannot reach DoubleAgent

- Start the Agent API in Burp.
- Confirm `curl -s http://127.0.0.1:8777/api/health` succeeds.
- Check whether another process is using port `8777`.
- Keep the configured URL on loopback.

## Model connection test fails

- Use the exact API base and model ID.
- For OpenAI-compatible servers, verify `<base>/models` before changing Agent B.
- Confirm whether the base requires `/v1`.
- For Anthropic, use the native API base and an Anthropic key.
- For Bedrock, use a Bedrock bearer key and a model or inference profile available in the configured region.

## The macOS app does not open

Source-built applications are ad-hoc signed unless a Developer ID is supplied. Verify the build:

```bash
codesign --verify --deep --strict "Agent B.app"
```

If macOS blocks a downloaded, non-notarized community build, build from source or use the source runner.

## A run says it completed but findings are missing

Treat Burp's persisted finding state as authoritative. Check linked findings, versions, audit records, and Agent B events. Do not accept the final model message as proof of persistence.

## MCP tools are missing

1. Confirm that **MCP Server** is installed under **Extensions → Installed** and is loaded.
2. Open Burp's **MCP** tab and confirm the server is enabled on `127.0.0.1:9876`.
3. Probe the SSE listener:

   ```bash
   curl --max-time 2 -N -i http://127.0.0.1:9876/
   ```

   Expect an event-stream response containing an `endpoint` event. The timeout is normal for an open SSE stream.

4. With Agent A's API running, trigger and then re-read capability discovery:

   ```bash
   curl -s "http://127.0.0.1:8777/api/agent/mcp/capabilities?refresh=true"
   curl -s http://127.0.0.1:8777/api/agent/mcp/capabilities
   curl -s http://127.0.0.1:8777/api/agent/burp/capabilities
   ```

5. Check the **MCP Server** and **Double Agent** extension output for connection or tool-discovery errors.
6. Confirm that no other process is using port `9876`. If you changed the port, start Burp with a matching `PORTSWIGGER_MCP_URL` value.
7. Do not send loopback MCP control traffic through Burp's assessment proxy.

If the listener works but a particular action is absent, the installed MCP Server version or Burp edition may not expose it. DoubleAgent reports callback fallbacks separately and will leave MCP-only work unavailable rather than inventing success. See [PortSwigger MCP integration](PortSwigger-MCP.md) for the capability table and security model.
