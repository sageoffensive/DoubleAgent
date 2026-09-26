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

## Discuss, share files, and make decisions

Select **Discuss** beside the message box for advice, document review, screenshot interpretation, and help drafting questions. Discuss has no assessment tools, even when bootstrap has already been sent. To return to the existing Burp workflow, select **Assessment chat** or use the queue controls.

Use **Attach files**, drag files onto the message box, or paste a screenshot. Agent B accepts text/Markdown/CSV/JSON/log/XML/YAML files and PNG/JPEG/WebP images. You can attach four files at once: text files up to 120 KB each (160 KB combined), images up to 3 MB each. PDF, Office files and archives need exporting to text or images first.

For images, open **Settings → Edit connection** and enable **Supports image input** for a model and server that support vision. This option starts disabled and the connection test does not verify vision. Files stay on this computer until sent; pressing **Send** includes them in the request to your selected model provider. Review sensitive content yourself, especially screenshots, whose pixels are not redacted.

Use **Download response** for a Markdown copy, the attachment's filename link for its stored copy, or **Export chat** for the transcript. Text attachments have common credentials redacted, so downloaded copies can differ from originals. Local files are owner-readable but unencrypted. **New conversation** clears them; export first if you need a copy. After restarting the app, attach relevant files again for model discussion.

Existing recommendations appear in **Ideas & recommendations** with evidence, confidence and the suggested next step. Save or dismiss them, or select **Discuss** to prepare a follow-up message. These decisions never authorize an action. They persist across runs and app restarts until you start a new conversation.

Questions appear in a dedicated card with choices and a free-text answer. Approval cards require **Approve once** or **Do not approve**. Stopping or restarting cancels pending questions and approvals. Messages sent during a run receive an acknowledgement and are considered at the next response boundary.

## Agent A finding validation

After bootstrap, use **Validate Agent A findings**. Agent B snapshots eligible findings, gathers linked evidence, and writes one persisted disposition per finding. Completion is blocked while linked findings remain unaccounted for.

## Duplicate review

Duplicate candidates are shortlisted deterministically. A merge requires compatible endpoint, parameter, root cause, and evidence. The surviving finding keeps its audit trail and linked identifiers.

## Model comparison

Hold the target, queue, skill set, tool schema, maximum steps, and output budget constant. Record the model and connection used for the run. Do not credit reasoning for a result when another condition changed.
