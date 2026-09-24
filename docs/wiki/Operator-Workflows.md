# Operator workflows

## First authorized assessment

1. In Burp, confirm the target is in scope.
2. In Agent A's **Agent AI** tab, start the API.
3. Start Agent B in the browser or macOS app.
4. Add a model connection and select **Test connection**.
5. Select **Send bootstrap**.
6. Read the target and scope shown in Agent B.
7. Give Agent B a specific authorized task or fetch an item from Agent A's queue.
8. Review questions and approvals as the run progresses.
9. Confirm the final requests, responses, and finding state in Burp.

The working relationship is always:

**Agent A evidence → your judgment → Agent B assistance**

Agent B may propose and orchestrate work, but Agent A remains the source of truth and you remain accountable for scope.

## Regular chat

1. Start Agent B.
2. Create a new conversation.
3. Chat normally without selecting **Send bootstrap**.

A regular chat does not automatically receive Burp context or assessment tools.

## Agent A finding validation

After bootstrap, use **Validate Agent A findings**. Agent B snapshots eligible findings, gathers linked evidence, and writes one persisted disposition per finding. Completion is blocked while linked findings remain unaccounted for.

## Duplicate review

Duplicate candidates are shortlisted deterministically. A merge requires compatible endpoint, parameter, root cause, and evidence. The surviving finding keeps its audit trail and linked identifiers.

## Model comparison

Hold the target, queue, skill set, tool schema, maximum steps, and output budget constant. Record the model and connection used for the run. Do not credit reasoning for a result when another condition changed.
