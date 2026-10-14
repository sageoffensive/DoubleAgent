# Agent B v3.2.3

Assessment tasks now honor the chat's thinking preference. During duplicate review, if a connection supports optional thinking and exhausts its output budget before making a tool call, Agent B retries with optional thinking disabled. An explicit operator preference is preserved. The saved comparison population, accepted verdicts, scope controls and tools stay in place.

Includes the v3.2.2 dedupe workflow fix; the DoubleAgent extension must also be updated to v3.2.2.

Stopping a streaming response also cancels at the next received chunk, including servers that close the HTTP connection after streaming.
