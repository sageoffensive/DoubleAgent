# Operator workflows

## Regular chat

1. Start Agent B.
2. Create a new conversation.
3. Chat normally without loading Burp context or assessment tools.

## Burp assessment

1. Confirm the target is correctly scoped in Burp.
2. Start the DoubleAgent API.
3. In Agent B, select **Send bootstrap**.
4. Review the loaded target and operating context.
5. Fetch a queued item or provide a specific authorized task.
6. Review questions, approvals, requests, responses, and finding updates as the run progresses.
7. Confirm final state in Burp rather than relying on the model's final message.

## Agent A finding validation

Use **Validate Agent A findings** after bootstrap. Agent B snapshots eligible findings, gathers linked evidence, and writes one persisted disposition per finding. Completion is blocked while linked findings remain unaccounted for.

## Duplicate review

Duplicate candidates are shortlisted deterministically. A merge requires compatible endpoint, parameter, root cause, and evidence. The surviving finding retains an audit trail and linked identifiers.

## Model comparison

For a useful comparison, hold the target, queue, skill set, tool schema, maximum steps, and output budget constant. Record the selected model and connection with the run. Do not attribute a difference to reasoning when another field changed.
