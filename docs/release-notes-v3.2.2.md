# Agent B and DoubleAgent v3.2.2

“Dedupe the list” now starts the saved-finding duplicate-review workflow. Agent B compares the complete linked population, writes duplicate verdicts to DoubleAgent and reports only accepted changes. A consolidated list in a chat reply is not treated as a saved change.

Duplicates are hidden from the normal findings view, preserving their IDs, evidence and canonical references. **Show hidden** reveals them for review. Reclassifying a duplicate restores its normal visibility. Duplicate review sends no target traffic, and unrelated findings and canonical findings are retained.

This fix requires both the updated Agent B app and reloaded DoubleAgent extension.
