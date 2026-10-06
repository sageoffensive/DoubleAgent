const $ = selector => document.querySelector(selector);

let last = 0;
let busy = false;
let renderedFeed = null;
let cache = {messages: [], modelStream: '', modelRun: 0};
let modelOptions = [];
let providerOptions = [];
let skillCatalog = [];
let loadedModelUrl = '';
let attachmentDrafts = [];
let uploading = false;
let sending = false;
const pendingActions = new Set();
function lockAction(key, handler, control) {
  return async function(event) {
    if (pendingActions.has(key)) { event?.preventDefault(); return; }
    pendingActions.add(key);
    if (control) control.disabled = true;
    try { return await handler.call(this, event); }
    finally {
      pendingActions.delete(key);
      if (control) control.disabled = false;
      if (latestState.status) render(latestState);
    }
  };
}
let latestState = {};
let questionKey = null;
let suggestionsKey = null;
let notebookKey = null;
let notebookRevision = 0;
let notebookSaving = false;
let workspace = 'conversation';
let settingsSection = 'models';
let harnessOnline = false;
let conversationScroll = 0;
let followConversation = true;

function showNotice(message) {
  $('#ui-notice-text').textContent = message;
  $('#ui-notice').classList.remove('hidden');
}
$('#dismiss-notice').onclick = () => $('#ui-notice').classList.add('hidden');

function selectSettings(name, focus = false) {
  settingsSection = name;
  document.querySelectorAll('[data-settings]').forEach(button => {
    const selected = button.dataset.settings === name;
    button.setAttribute('aria-selected', String(selected));
    button.tabIndex = selected ? 0 : -1;
    $(`#settings-${button.dataset.settings}`).classList.toggle('hidden', !selected);
    if (selected && focus) button.focus();
  });
}

function bindTabs(selector, select, field) {
  const buttons = [...document.querySelectorAll(selector)];
  buttons.forEach((button, index) => {
    button.onclick = () => select(button.dataset[field]);
    button.onkeydown = event => {
      let next = index;
      if (event.key === 'ArrowRight') next = (index + 1) % buttons.length;
      else if (event.key === 'ArrowLeft') next = (index + buttons.length - 1) % buttons.length;
      else if (event.key === 'Home') next = 0;
      else if (event.key === 'End') next = buttons.length - 1;
      else return;
      event.preventDefault();
      select(buttons[next].dataset[field], true);
    };
  });
}
bindTabs('[data-settings]', selectSettings, 'settings');

function updateScrollControl() {
  if (workspace !== 'conversation') return;
  const timeline = $('#timeline');
  conversationScroll = timeline.scrollTop;
  followConversation = timeline.scrollHeight - timeline.scrollTop - timeline.clientHeight < 80;
  $('#jump-latest').classList.toggle('hidden', timeline.scrollHeight - timeline.scrollTop - timeline.clientHeight < 80);
}
$('#timeline').addEventListener('scroll', updateScrollControl);
$('#jump-latest').onclick = () => {
  const timeline = $('#timeline');
  timeline.scrollTop = timeline.scrollHeight;
  updateScrollControl();
};

function updateComposer() {
  const active = ['starting', 'running', 'waiting', 'stopping'].includes(latestState.status);
  const approval = latestState.pending_question?.id.startsWith('approval-');
  const blocked = latestState.status === 'stopping' || approval || !harnessOnline || !latestState.settings?.model || (active && attachmentDrafts.length > 0);
  const button = $('#composer button[type="submit"]');
  button.disabled = blocked || uploading || sending || !($('#message').value.trim() || attachmentDrafts.length);
  button.textContent = sending ? 'Sending…' : 'Send';
  button.setAttribute('aria-label', 'Send');
  button.title = approval ? 'Choose an approval option above'
    : latestState.status === 'stopping' ? 'Wait for the run to stop'
    : active && attachmentDrafts.length ? 'Remove attachments or wait for the current response'
    : active ? 'Guide the current run at its next response boundary'
    : !harnessOnline ? 'Waiting for Agent B to reconnect'
    : !latestState.settings?.model ? 'Add a model connection in Settings first'
    : 'Send message';
  $('#attach-files').disabled = active || Boolean(latestState.pending_question) || !harnessOnline || uploading || sending;
  $('#connection-guidance').classList.toggle('hidden', Boolean(latestState.settings?.model));
  $('#composer').classList.toggle('hidden', Boolean(approval));
  $('#message').placeholder = latestState.pending_question ? 'Reply to Agent B…' : 'Message Agent B…';
  $('#question').querySelectorAll('button').forEach(option => { option.disabled = sending; });
}
$('#message').addEventListener('input', updateComposer);


function composerStatus(text) { $('#composer-status').textContent = text; }

function renderAttachments() {
  const list = $('#attachment-list');
  list.classList.toggle('hidden', !attachmentDrafts.length);
  list.innerHTML = attachmentDrafts.map((f, index) => `<span class="attachment-chip">${f.mime.startsWith('image/') ? `<img class="attachment-thumbnail" src="/api/files/${encodeURIComponent(f.id)}/preview" alt="${esc(f.name)}">` : ''}${esc(f.name)} · ${Math.ceil(f.size / 1024)} KB ${/\.(js|jsx|mjs)$/i.test(f.name) ? `<button type="button" data-analyze-js="${index}" aria-label="Analyze ${esc(f.name)}">Analyze JS</button>` : ''}<button type="button" data-remove-file="${index}" aria-label="Remove ${esc(f.name)}">×</button></span>`).join('');
  updateComposer();
  list.querySelectorAll('[data-remove-file]').forEach(button => {
    button.onclick = () => { attachmentDrafts.splice(Number(button.dataset.removeFile), 1); renderAttachments(); };
  });
  list.querySelectorAll('[data-analyze-js]').forEach(button => {
    button.onclick = () => reviewJavaScript(attachmentDrafts[Number(button.dataset.analyzeJs)]);
  });
}

const javascriptDialog = $('#javascript-dialog');
$('#close-javascript').onclick = $('#done-javascript').onclick = () => javascriptDialog.close();
async function reviewJavaScript(file) {
  if (!file) return;
  try {
    const report = await api(`/api/files/${encodeURIComponent(file.id)}/javascript`);
    $('#javascript-summary').textContent = `${file.name}: ${report.summary.total} static candidates${report.truncated ? ' · results limited to 100' : ''}.`;
    const sections = [report.notice];
    for (const [category, findings] of Object.entries(report.findings)) {
      if (!findings.length) continue;
      sections.push(`${category.toUpperCase()} (${findings.length})\n` + findings.map(item => `${item.source}:${item.position.line}:${item.position.column}  ${item.value}${item.kind ? ` (${item.kind})` : ''}`).join('\n'));
    }
    $('#javascript-report').textContent = sections.join('\n\n');
    $('#download-javascript-report').href = `/api/files/${encodeURIComponent(file.id)}/javascript/download`;
    javascriptDialog.showModal();
  } catch (error) { composerStatus(error.message); }
}

async function attachFiles(files) {
  if (uploading || sending) return;
  if (latestState.pending_question || ['starting', 'running', 'waiting', 'stopping'].includes(latestState.status)) {
    composerStatus('Wait for the response or stop the run before attaching files.'); return;
  }
  if (attachmentDrafts.length + files.length > 4) { composerStatus('Attach up to four files per message.'); return; }
  uploading = true;
  updateComposer();
  try {
    for (const file of files) {
      if (file.size > 3 * 1024 * 1024) throw new Error(`${file.name}: maximum file size is 3 MB.`);
      if (/\.(png|jpe?g|webp)$/i.test(file.name) && !modelOption(latestState.settings?.model)?.supports_images) {
        throw new Error('This connection has image input disabled. Enable it in Settings for a vision-capable model.');
      }
      composerStatus(`Adding ${file.name}…`);
      const encoded = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result).split(',')[1]);
        reader.onerror = () => reject(new Error('Could not read the selected file.'));
        reader.readAsDataURL(file);
      });
      attachmentDrafts.push(await api('/api/files', {method: 'POST', body: JSON.stringify({name: file.name, data: encoded})}));
      renderAttachments();
    }
    composerStatus('');
  } catch (error) { composerStatus(error.message); }
  finally { uploading = false; updateComposer(); $('#file-picker').value = ''; }
}

$('#attach-files').onclick = () => $('#file-picker').click();
$('#file-picker').onchange = event => attachFiles([...event.target.files]);
$('#message').addEventListener('paste', event => {
  const files = [...(event.clipboardData?.files || [])];
  if (files.length) { event.preventDefault(); attachFiles(files); }
});
$('#composer').addEventListener('dragover', event => { event.preventDefault(); });
$('#composer').addEventListener('drop', event => {
  event.preventDefault(); attachFiles([...event.dataTransfer.files]);
});

function modelOption(id) {
  return modelOptions.find(option => option.id === id);
}

const compactNavigation = window.matchMedia('(max-width:1000px)');
function syncNavigation() {
  const open = compactNavigation.matches && document.querySelector('aside').classList.contains('open');
  document.querySelector('aside').inert = compactNavigation.matches && !open;
  document.querySelector('main').inert = open;
  $('#nav-backdrop').classList.toggle('hidden', !open);
  $('#open-nav').setAttribute('aria-expanded', String(open));
}
function closeNavigation() {
  document.querySelector('aside').classList.remove('open');
  syncNavigation();
}
$('#open-nav').onclick = () => {
  document.querySelector('aside').classList.add('open');
  syncNavigation();
  $('#close-nav').focus();
};
$('#close-nav').onclick = $('#nav-backdrop').onclick = () => { closeNavigation(); $('#open-nav').focus(); };
compactNavigation.addEventListener('change', closeNavigation);
syncNavigation();
document.addEventListener('keydown', event => {
  if (!compactNavigation.matches || !document.querySelector('aside').classList.contains('open')) return;
  if (event.key === 'Escape') { closeNavigation(); $('#open-nav').focus(); }
  if (event.key === 'Tab') {
    const items = [...document.querySelector('aside').querySelectorAll('button:not(:disabled), a[href]')];
    const first = items[0], last = items[items.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  }
});

async function api(path, options = {}) {
  const response = await fetch(path, {headers: {'Content-Type': 'application/json'}, ...options});
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || `HTTP ${response.status}`);
  return value;
}

function dot(element, state) {
  element.className = `dot ${state ? 'ok' : 'bad'}`;
}

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

function visibleMessage(value) {
  const message = String(value ?? '');
  const formatted = text => esc(text).replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');
  if (message.length <= 1800) return formatted(message);
  return `<details class="full-response"><summary aria-label="Toggle full response"><span class="response-preview">${formatted(message.slice(0, 1600))}…</span><span class="response-toggle">Read full response · ${message.length.toLocaleString()} characters</span></summary><div>${formatted(message)}</div></details>`;
}

function render(value) {
  const keepFollowing = renderedFeed === null || followConversation;
  latestState = value;
  if (value.settings?.model_options) modelOptions = value.settings.model_options;
  const stopping = value.status === 'stopping';
  const bootstrapped = Boolean(value.burp_prompt_loaded);
  $('#run-state').textContent = stopping ? 'Stopping…' : ({idle: 'Ready', waiting: 'Needs your input', running: 'Working', starting: 'Starting…', stopped: 'Stopped', complete: 'Complete', error: 'Needs attention'}[value.status] || value.status);
  $('#step-label').textContent = `Step ${value.step} of ${value.max_steps}`;
  $('#step-meter').style.width = `${Math.min(100, value.step / Math.max(1, value.max_steps) * 100)}%`;
  const findingProgress = value.finding_validation_progress || {};
  const findingProgressEl = $('#finding-progress');
  const linkedFindingCount = Number(findingProgress.linked || 0);
  findingProgressEl.classList.toggle('hidden', linkedFindingCount < 1);
  findingProgressEl.textContent = linkedFindingCount > 0
    ? `${Number(findingProgress.verdicts_recorded || 0)} verdicts saved · ${linkedFindingCount} linked`
    : '';

  const active = ['starting', 'running', 'waiting', 'stopping'].includes(value.status);
  $('#run-dot').className = `dot ${value.status === 'running' ? 'ok' : active ? 'warn' : ''}`;
  $('#stop').disabled = !active || stopping;
  $('#clear').disabled = active || sending || pendingActions.has('clear');
  $('#stop').textContent = stopping ? 'Stopping…' : 'Stop current run';
  $('#fetch').disabled = active || !bootstrapped;
  $('#validate-a').disabled = active || !bootstrapped || pendingActions.has('validate');
  $('#fetch').classList.toggle('primary', bootstrapped);
  $('#bootstrap').disabled = active || bootstrapped || pendingActions.has('bootstrap');
  $('#bootstrap').classList.toggle('primary', !bootstrapped);
  $('#bootstrap').textContent = bootstrapped ? 'Burp context loaded' : 'Connect to Burp';
  $('#bootstrap').title = bootstrapped
    ? 'Bootstrap already sent in this conversation'
    : 'Load the Burp context for this conversation';
  $('#fetch').title = bootstrapped ? 'Fetch the next Double Agent work item' : 'Connect to Burp first';
  $('#validate-a').title = bootstrapped ? 'Validate current Agent A findings' : 'Connect to Burp first';
  const targetKnown = Boolean(value.target_url);
  $('#seed-surface').disabled = active || !bootstrapped || !targetKnown;
  $('#seed-surface').title = !bootstrapped ? 'Connect to Burp first'
    : !targetKnown ? 'Fetch a target first so seed routes resolve'
    : 'Add OpenAPI/sitemap/URL routes to coverage and discovery';
  const bootstrapGuidance = $('#bootstrap-guidance');
  bootstrapGuidance.textContent = bootstrapped
    ? 'Burp context loaded. Choose a task below.'
    : 'Connect to Burp to start assessment work.';
  bootstrapGuidance.classList.toggle('ready', bootstrapped);
  const activeSkills = value.active_skills || [];
  $('#active-skills').innerHTML = activeSkills.length
    ? activeSkills.map(skill => `<span title="${esc(skill.description)}">${esc(skill.name)}</span>`).join('')
    : '<span class="muted-skill">None · comparison control</span>';

  const doubleAgent = value.health.double_agent;
  dot($('#burp-dot'), doubleAgent.ok);
  $('#burp-state').textContent = doubleAgent.ok ? 'Connected' : 'Unavailable · check Burp extension';
  $('#burp-state').title = typeof doubleAgent.detail === 'string' ? doubleAgent.detail : value.settings.double_agent_url;
  const model = value.health.model;
  dot($('#model-dot'), model.ok);
  $('#model-name').textContent = modelOption(value.settings.model)?.label || value.settings.model || 'No model connection';
  $('#model-state').textContent = model.ok ? (String(model.detail).startsWith('configured') ? 'Configured · test in Settings' : 'Model available') : !value.settings.model ? 'Add a connection in Settings' : 'Unavailable · check connection';
  $('#model-state').title = String(model.detail || '');
  const targetUrl = value.target_url || '';
  $('#target-row').classList.toggle('hidden', !targetUrl);
  if (targetUrl) {
    $('#target-link').href = targetUrl;
    $('#target-link').textContent = targetUrl;
    $('#target-link').title = `Open ${targetUrl} in your browser`;
  }
  const streamPanel = $('#model-stream-panel');
  const streamDelta = value.model_stream || '';
  const streamOffset = Number(value.model_stream_offset || 0);
  const streamLength = Number(value.model_stream_length || 0);
  const runChanged = cache.modelRun !== value.started;
  if (runChanged) {
    cache.modelRun = value.started;
    cache.modelStream = '';
    streamPanel.open = false;
  }
  if (streamOffset === cache.modelStream.length) {
    cache.modelStream += streamDelta;
  } else if (streamOffset === 0) {
    cache.modelStream = streamDelta;
  } else {
    cache.modelStream = cache.modelStream.slice(0, streamOffset) + streamDelta;
  }
  const streamElement = $('#model-stream');
  if (runChanged || streamDelta || streamElement.dataset.length !== String(cache.modelStream.length)) {
    const followStream = streamElement.scrollHeight - streamElement.scrollTop - streamElement.clientHeight < 40;
    streamElement.textContent = cache.modelStream || 'No model output yet.';
    streamElement.dataset.length = String(cache.modelStream.length);
    if (followStream) streamElement.scrollTop = streamElement.scrollHeight;
  }
  const modelElapsed = ['starting', 'running'].includes(value.status) && value.model_stream_started
    ? Math.max(0, Math.floor(Date.now() / 1000 - Number(value.model_stream_started)))
    : 0;
  const streamChannel = String(value.model_stream_channel || '');
  let activityLabel = 'Model activity';
  if (value.status === 'waiting') activityLabel = 'Waiting for your answer';
  else if (stopping) activityLabel = 'Stopping';
  else if (active) {
    if (streamChannel === 'Thinking') activityLabel = 'Thinking';
    else if (streamChannel === 'Model commentary') activityLabel = 'Planning next action';
    else if (streamChannel === 'Response') activityLabel = 'Writing response';
    else if (streamChannel === 'Tool call') activityLabel = 'Choosing a tool';
    else if (streamChannel === 'Harness') activityLabel = 'Applying safety checks';
    else if (streamChannel === 'Finish') activityLabel = 'Finishing model step';
    else activityLabel = 'Starting model';
  } else if (streamLength) {
    activityLabel = value.model_reasoning_seen ? 'Reasoning and activity' : 'Last model activity';
  }
  $('#model-activity-label').textContent = 'Thinking & activity';
  $('#model-activity-dot').className = `activity-dot ${value.status === 'waiting' ? 'waiting' : active ? 'active' : streamLength ? 'complete' : ''}`;
  $('#model-stream-source').textContent = value.model_reasoning_seen
    ? 'Provider-exposed reasoning'
    : value.model_reasoning_requested
      ? 'Waiting for provider reasoning'
      : 'Action commentary';
  streamPanel.classList.toggle('active', active);
  streamPanel.classList.toggle('hidden', !active && !streamLength);
  streamPanel.classList.toggle('has-reasoning', Boolean(value.model_reasoning_seen));
  $('#model-stream-state').textContent = streamLength || active
    ? value.status === 'waiting' ? activityLabel : `${activityLabel} · Step ${value.model_stream_step}${modelElapsed ? ` · ${modelElapsed}s` : ''}`
    : `Waiting for ${modelOption(value.settings.model)?.label || 'model'}`;

  const plan = value.assessment_plan || {};
  const planPanel = $('#assessment-plan-panel');
  const hasPlan = Number(plan.route_count || 0) > 0 || (plan.attack_families || []).length > 0;
  planPanel.classList.toggle('hidden', !hasPlan);
  if (hasPlan) {
    const priorities = (plan.priorities || []).slice(0, 8);
    const families = plan.attack_families || [];
    const plannedTests = plan.planned_tests || [];
    $('#assessment-plan-title').textContent = `Plan of attack · ${plan.route_count || 0} routes · ${families.length} attack families · ${plannedTests.length} test tracks`;
    $('#assessment-plan').innerHTML = `
      <div class="plan-section"><strong>Highest-value routes</strong>
        ${priorities.length ? `<ol>${priorities.map(item => `<li><code>${esc(item.route)}</code><span>score ${esc(item.score)}</span></li>`).join('')}</ol>` : '<p>No concrete route is available yet.</p>'}
      </div>
      <div class="plan-section"><strong>Coverage matrix</strong><div class="family-grid">
        ${families.map(item => `<div><span class="family-state ${esc(item.disposition)}">${esc(item.disposition)}</span>${esc(item.title)}</div>`).join('')}
      </div></div>`;
  }

  renderCoverage(value.coverage_summary || {});

  cache.messages = value.messages;
  if (value.events.length) last = value.events[value.events.length - 1].id;

  // Keep saved thinking collapsible alongside questions and final results.
  // Per-step narration and progress chatter stay out of the transcript.
  const transcript = cache.messages.filter(message => {
    if (message.role !== 'assistant') return true;
    const m = message.metadata || {};
    return !(m.intermediate || m.progress || (m.internet_request && m.question_id === value.pending_question?.id));
  });
  const feedKey = transcript.map(message => `message:${message.id}`).join('|');
  const timeline = $('#timeline');

  if (feedKey !== renderedFeed) {
    const position = timeline.scrollTop;
    const expandedThinking = new Set([...timeline.querySelectorAll('details[data-thinking-id][open]')].map(item => item.dataset.thinkingId));
    const follow = workspace === 'conversation' && timeline.scrollHeight - position - timeline.clientHeight < 80;
    const items = transcript.map(message => {
      const meta = message.metadata || {};
      const harnessMessage = message.role === 'assistant' && (meta.progress || meta.connection || meta.harness_status);
      const thinking = message.role === 'assistant' && meta.thinking;
      const speaker = message.role === 'user' ? 'You' : harnessMessage ? 'Harness status' : thinking ? 'Thinking' : 'Agent B';
      const content = message.role === 'assistant'
        ? String(meta.internet_request?.summary || message.content || '').replace(/^(?:[\t ]*\r?\n)+/, '')
        : message.content;
      if (thinking) return `
      <details class="message thinking" data-thinking-id="${esc(message.id)}"${expandedThinking.has(String(message.id)) ? ' open' : ''}>
        <summary>Thinking</summary>
        <div class="bubble">${visibleMessage(content)}</div>
      </details>`;
      return `
      <div class="message ${esc(message.role)} ${harnessMessage ? 'harness-status' : ''} ${thinking ? 'thinking' : ''}">
        <div class="meta">${speaker}</div>
        <div class="bubble">${visibleMessage(content)}${meta.internet_request ? internetDetails(meta.internet_request) : message.role === 'assistant' && meta.question_id && meta.reason ? `<details class="question-reason"><summary>More context</summary><p>${esc(meta.reason)}</p></details>` : ''}${(meta.attachments || []).map(f => `<a class="attachment-download" href="/api/files/${encodeURIComponent(f.id)}" download>${f.mime.startsWith('image/') ? `<img class="attachment-thumbnail" src="/api/files/${encodeURIComponent(f.id)}/preview" alt="${esc(f.name)}">` : ''}${esc(f.name)} ↓</a>`).join('')}</div>
      </div>`;
    });

    timeline.innerHTML = items.length ? items.join('') : `
      <div class="empty"><div><img class="empty-mark" src="/agent-b-logo.png" alt="" width="72" height="72"><strong>How can I help?</strong><p>Send a message or attach a file.</p></div></div>`;
    timeline.scrollTop = follow ? timeline.scrollHeight : position;
    renderedFeed = feedKey;
    updateScrollControl();
  }

  const pending = value.pending_question;
  const question = $('#question');
  if (pending && questionKey !== pending.id) {
    questionKey = pending.id;
    question.classList.toggle('hidden', !(pending.options || []).length);
    const approval = pending.id.startsWith('approval-');
    question.innerHTML = pending.internet_request
      ? internetQuestion(pending.internet_request, pending.options || [])
      : `<div class="eyebrow">${approval ? 'YOUR APPROVAL IS REQUIRED' : 'CHOOSE AN ANSWER'}</div><div>${
      (pending.options || []).map(option => `<button data-answer="${esc(option)}">${esc(option)}</button>`).join('')
    }</div>${approval ? '<p class="hint">Applies once to this action.</p>' : ''}`;
    question.querySelectorAll('[data-answer]').forEach(button => {
      button.onclick = () => answer(pending.id, button.dataset.answer);
    });
  } else if (!pending) {
    questionKey = null;
    question.classList.add('hidden');
  }
  renderSuggestions(value.route_recommendations || []);
  renderNotebook(value.notebook || {}, active);
  updateComposer();
  if (workspace === 'conversation' && keepFollowing) requestAnimationFrame(() => {
    if (workspace !== 'conversation') return;
    $('#timeline').scrollTop = $('#timeline').scrollHeight;
    updateScrollControl();
  });
  $('#settings-form button[type="submit"]').disabled = active || pendingActions.has('settings');
  $('#add-model').disabled = active;
  $('#test-model').disabled = active || !$('#model-choice').value || pendingActions.has('connection-test');
  $('#edit-model').disabled = active || !modelOption($('#model-choice').value)?.custom;
  $('#remove-model').disabled = active || !modelOption($('#model-choice').value)?.custom || pendingActions.has('remove-model');
}

function internetDetails(request) {
  return `<details class="internet-request-details"><summary>Request details</summary><dl>${[
    ['Destination', request.destination], ['Sending', request.sending],
    ['Fetching', request.fetching], ['Reason', request.reason], ['Model sharing', request.sharing]
  ].map(([label, text]) => `<dt>${label}</dt><dd>${esc(text || '')}</dd>`).join('')}</dl></details>`;
}

function internetQuestion(request, options) {
  return `<div class="eyebrow">INTERNET ACCESS</div><p class="internet-summary">${esc(request.summary)}</p><div class="internet-choices">${
    options.map(option => `<button data-answer="${esc(option)}"${option === 'Allow' ? ' class="primary"' : ''}>${esc(option)}</button>`).join('')
  }</div>${internetDetails(request)}`;
}

function renderNotebook(notebook, active) {
  const enabled = Boolean(notebook.burp_context_enabled);
  $('#burp-discussion-context').checked = enabled;
  $('#burp-discussion-context').disabled = active || notebookSaving;
  $('#refresh-discussion-context').disabled = !enabled || active || notebookSaving;
  $('#edit-notebook').disabled = active || notebookSaving;
  const snapshot = notebook.snapshot || {};
  const captured = snapshot.captured_at ? new Date(snapshot.captured_at * 1000).toLocaleTimeString() : '';
  const stale = snapshot.captured_at && Date.now() / 1000 - snapshot.captured_at > 60;
  $('#snapshot-status').textContent = !enabled ? 'Burp context off' : !snapshot.status ? 'Refresh or send a message to capture context'
    : `${snapshot.status === 'ready' ? 'Snapshot captured' : snapshot.status.replaceAll('_', ' ')}${captured ? ` at ${captured}` : ''}${stale ? ' · refresh before relying on it' : ''}`;
  const key = JSON.stringify(notebook);
  if (key === notebookKey) return;
  notebookKey = key;
  $('#notebook-summary').textContent = notebook.bound_target || 'Saved on this Mac';
  $('#notebook-objective').textContent = notebook.objective || 'Add your objective, facts, questions and decisions.';
  $('#notebook-notes').innerHTML = [['facts', 'Confirmed facts'], ['questions', 'Open questions'], ['decisions', 'Decisions']].filter(([key]) => notebook[key]).map(([key, label]) => `<section><strong>${label}</strong><p>${esc(notebook[key])}</p></section>`).join('');
  const findings = snapshot.findings || {};
  const queue = snapshot.queue || {};
  $('#notebook-snapshot').innerHTML = enabled && snapshot.status ? `
    ${snapshot.target ? `<p class="hint">Target: ${esc(snapshot.target)}</p>` : ''}
    ${(snapshot.blockers || []).map(reason => `<p class="snapshot-warning">${esc(reason)}</p>`).join('')}
    ${snapshot.findings ? `<p class="hint">${esc(findings.shown)} ${findings.shown === 1 ? 'finding' : 'findings'} shown${findings.limited ? ' · bounded sample' : ''} · ${esc(queue.shown || 0)} queue ${queue.shown === 1 ? 'item' : 'items'} shown${queue.limited ? ' · bounded sample' : ''}</p>` : ''}
    <details class="snapshot-detail"><summary>Source references and captured state</summary><pre>${esc(JSON.stringify(snapshot, null, 2))}</pre></details>` : '';
  $('#notebook-files').innerHTML = notebook.files?.length ? `<strong class="notebook-files-label">Recent files</strong><div class="notebook-file-list">${notebook.files.map(file => `
    <div><a class="download-link" href="/api/files/${encodeURIComponent(file.id)}" download>${esc(file.name)}</a><button type="button" data-reuse-file="${esc(file.id)}">Use in message</button></div>`).join('')}</div>` : '';
  $('#notebook-files').querySelectorAll('[data-reuse-file]').forEach(button => {
    button.onclick = () => {
      if (['starting', 'running', 'waiting', 'stopping'].includes(latestState.status) || uploading || sending) {
        composerStatus('Wait for the response or stop the run before adding a file.'); return;
      }
      const file = latestState.notebook?.files?.find(item => item.id === button.dataset.reuseFile);
      if (!file || attachmentDrafts.some(item => item.id === file.id)) return;
      if (attachmentDrafts.length >= 4) { composerStatus('Attach up to four files per message.'); return; }
      if (file.mime.startsWith('image/') && !modelOption(latestState.settings?.model)?.supports_images) {
        composerStatus('Enable image input on a vision-capable connection before using this image.'); return;
      }
      attachmentDrafts.push(file);
      $('#settings-dialog').close();
      renderAttachments();
      composerStatus('Stored file added. It will be sent with your message.');
      updateComposer();
      $('#message').focus();
    };
  });
}

const notebookDialog = $('#notebook-dialog');
$('#edit-notebook').onclick = () => {
  const notebook = latestState.notebook || {};
  notebookRevision = notebook.revision || 0;
  for (const field of ['objective', 'facts', 'questions', 'decisions']) {
    $('#notebook-form').elements.namedItem(field).value = notebook[field] || '';
  }
  $('#notebook-save-status').textContent = '';
  notebookDialog.showModal();
};
$('#close-notebook').onclick = $('#cancel-notebook').onclick = () => notebookDialog.close();
$('#notebook-form').onsubmit = async event => {
  event.preventDefault();
  if (notebookSaving) return;
  notebookSaving = true;
  const button = event.target.querySelector('[type="submit"]');
  button.disabled = true;
  try {
    await api('/api/notebook', {method: 'POST', body: JSON.stringify({...Object.fromEntries(new FormData(event.target)), revision: notebookRevision})});
    notebookDialog.close();
    composerStatus('Notebook saved for future discussions.');
    await poll();
  } catch (error) { $('#notebook-save-status').textContent = error.message; }
  finally { notebookSaving = false; button.disabled = false; }
};
$('#burp-discussion-context').onchange = async event => {
  notebookSaving = true;
  event.target.disabled = true;
  try {
    await api('/api/notebook', {method: 'POST', body: JSON.stringify({revision: latestState.notebook.revision, burp_context_enabled: event.target.checked})});
    await poll();
  } catch (error) { event.target.checked = !event.target.checked; composerStatus(error.message); }
  finally { notebookSaving = false; event.target.disabled = false; }
};
$('#refresh-discussion-context').onclick = async () => {
  notebookSaving = true;
  $('#refresh-discussion-context').disabled = true;
  try {
    composerStatus('Reading the current Burp findings and queue…');
    await api('/api/notebook/refresh', {method: 'POST', body: '{}'});
    await poll();
    composerStatus('Snapshot refreshed. View its source and capture time in Settings.');
  } catch (error) { composerStatus(error.message); }
  finally { notebookSaving = false; }
};

function renderSuggestions(items) {
  const key = JSON.stringify(items);
  if (key === suggestionsKey) return;
  suggestionsKey = key;
  $('#suggestions-panel').classList.toggle('hidden', !items.length);
  $('#suggestion-count').textContent = `· ${items.filter(s => s.decision !== 'dismissed').length} to review`;
  $('#suggestions').innerHTML = items.map(s => `<article class="suggestion ${s.decision === 'dismissed' ? 'dismissed' : ''}">
    <strong>${esc(s.subject || 'Recommendation')}</strong><span class="suggestion-state">${esc(s.route)} · ${esc(s.confidence || 'unrated')} confidence · ${esc(s.decision)}</span>
    <p>${esc(s.rationale)}</p><p>${esc(s.next_step || '')}</p>
    ${s.evidence?.length ? `<details><summary>Supporting evidence</summary><pre>${esc(JSON.stringify(s.evidence, null, 2))}</pre></details>` : ''}
    <div class="suggestion-actions"><button data-discuss="${esc(s.id)}">Discuss</button><button data-decision="saved" data-id="${esc(s.id)}">Save</button><button data-decision="${s.decision === 'dismissed' ? 'open' : 'dismissed'}" data-id="${esc(s.id)}">${s.decision === 'dismissed' ? 'Restore' : 'Dismiss'}</button></div></article>`).join('');
  $('#suggestions').querySelectorAll('[data-decision]').forEach(button => {
    button.onclick = async () => {
      try { await api('/api/suggestions/decide', {method: 'POST', body: JSON.stringify({id: button.dataset.id, decision: button.dataset.decision})}); await poll(); }
      catch (error) { composerStatus(error.message); }
    };
  });
  $('#suggestions').querySelectorAll('[data-discuss]').forEach(button => {
    button.onclick = () => {
      if (['starting', 'running', 'waiting', 'stopping'].includes(latestState.status)) {
        composerStatus('Finish or stop the current run before starting a separate discussion.'); return;
      }
      const s = items.find(item => item.id === button.dataset.discuss);
      $('#message').value = `Let's discuss recommendation ${s.id}: ${s.subject || ''}. Explain its supporting evidence, uncertainty, alternatives and missing information.`;
      updateComposer();
      $('#message').focus();
    };
  });
}

function renderCoverage(coverage) {
  const panel = $('#coverage-panel');
  const routes = coverage.routes || {};
  const params = coverage.parameters || {};
  const discovery = coverage.discovery || {};
  const tracks = coverage.tracks || {};
  const hasCoverage = coverage.available && (
    Number(routes.endpoints || 0) > 0 || Number(discovery.passes || 0) > 0 || Number(tracks.total || 0) > 0
  );
  panel.classList.toggle('hidden', !hasCoverage);
  if (!hasCoverage) return;
  // CSP blocks inline style attributes; carry the percent in data-pct and apply
  // it as a DOM property after the HTML is inserted.
  const bar = percent => `<div class="cov-meter"><i data-pct="${Math.min(100, Math.max(0, Number(percent) || 0))}"></i></div>`;
  const seedSources = (discovery.seed_sources || [])
    .map(source => `${esc(source.source || 'seed')}${source.routes ? ` (${source.routes})` : ''}`).join(', ');
  const discoveryState = discovery.plan_finalized
    ? 'finalized'
    : `pass ${discovery.passes || 0}, ${discovery.stable_passes || 0}/${discovery.required_stable_passes || 2} stable`;
  $('#coverage-title').textContent = `Coverage · routes ${routes.tested || 0}/${routes.endpoints || 0} · params ${params.tested || 0}/${params.total || 0}`;
  $('#coverage-sub').textContent = discovery.plan_finalized
    ? 'Discovery finalized'
    : `Discovery ${discovery.stable_passes || 0}/${discovery.required_stable_passes || 2} stable · ${discovery.frontier_remaining || 0} unexplored`;
  $('#coverage-body').innerHTML = `
    <div class="cov-grid">
      <div class="cov-cell"><strong>Routes tested · ${Math.round(Number(routes.coverage_percent) || 0)}%</strong>${bar(routes.coverage_percent)}
        <span>${routes.tested || 0} of ${routes.endpoints || 0} observed endpoints · ${routes.untested || 0} untested</span></div>
      <div class="cov-cell"><strong>Parameters tested · ${Math.round(Number(params.coverage_percent) || 0)}%</strong>${bar(params.coverage_percent)}
        <span>${params.tested || 0} of ${params.total || 0} · ${params.meaningful_untested || 0} meaningful untested</span></div>
    </div>
    <div class="cov-stats">
      <div><em>Discovery</em>${discoveryState} · ${discovery.visited || 0} routes visited · ${discovery.frontier_remaining || 0} unexplored</div>
      <div><em>Test tracks</em>${tracks.terminal || 0} of ${tracks.total || 0} complete · ${tracks.remaining || 0} remaining</div>
      ${seedSources ? `<div><em>Seed sources</em>${seedSources}</div>` : ''}
      ${(discovery.technologies || []).length ? `<div><em>Tech</em>${(discovery.technologies || []).map(esc).join(', ')}</div>` : ''}
    </div>
    <p class="cov-note">Denominator counts what Burp observed plus what discovery and seeding reached — untested/unexplored numbers flag blind spots. Use Seed coverage to add an OpenAPI spec, sitemap, or URL list.</p>`;
  $('#coverage-body').querySelectorAll('.cov-meter i').forEach(el => { el.style.width = `${el.dataset.pct}%`; });
}

async function poll() {
  if (busy) return;
  busy = true;
  try {
    const value = await api(`/api/state?after=${last}&stream_after=${cache.modelStream.length}`);
    harnessOnline = true;
    render(value);
  } catch (error) {
    harnessOnline = false;
    $('#run-state').textContent = 'Reconnecting…';
    updateComposer();
  } finally {
    busy = false;
  }
}

async function send(message, assessment = false) {
  if (sending || uploading) return;
  const pending = latestState.pending_question;
  if (pending && !assessment && !pending.id.startsWith('approval-') && latestState.status !== 'stopping') {
    if (attachmentDrafts.length) { composerStatus('Remove attachments before replying.'); return; }
    return answer(pending.id, message, true);
  }
  if (latestState.status === 'stopping' || latestState.pending_question || (assessment && ['starting', 'running', 'waiting'].includes(latestState.status))) {
    composerStatus(pending ? 'Choose an answer above.' : 'Wait for the current response.'); return;
  }
  if (!harnessOnline || !latestState.settings?.model) { composerStatus('Connect a model in Settings before sending.'); return; }
  const sentDraft = $('#message').value;
  const sentAttachments = attachmentDrafts.map(file => file.id);
  sending = true;
  updateComposer();
  $('#composer button[type="submit"]').disabled = true;
  try {
    const active = ['starting', 'running', 'waiting'].includes(latestState.status);
    const discussion = !assessment && (!active || latestState.discussion_mode || !latestState.burp_prompt_loaded);
    await api('/api/chat', {method: 'POST', body: JSON.stringify({message, thinking: null, discussion, attachments: assessment ? [] : attachmentDrafts.map(f => f.id)})});
    if (!assessment) {
      if ($('#message').value === sentDraft) $('#message').value = '';
      attachmentDrafts = attachmentDrafts.filter(file => !sentAttachments.includes(file.id));
      renderAttachments();
    }
    composerStatus('');
    await poll();
  } catch (error) {
    composerStatus(error.message);
  } finally {
    sending = false;
    updateComposer();
  }
}

async function answer(id, response, fromComposer = false) {
  if (sending || uploading) return;
  response = response.trim();
  if (!response || response.length > 4000) { composerStatus('Keep your reply between 1 and 4000 characters.'); return; }
  const sentDraft = $('#message').value;
  sending = true;
  updateComposer();
  try {
    await api(`/api/questions/${id}/answer`, {method: 'POST', body: JSON.stringify({answer: response})});
    if (fromComposer && $('#message').value === sentDraft) $('#message').value = '';
    composerStatus('');
    await poll();
  } catch (error) {
    composerStatus(error.message);
  } finally {
    sending = false;
    updateComposer();
  }
}

$('#composer').onsubmit = event => {
  event.preventDefault();
  const message = $('#message').value.trim();
  if (message || attachmentDrafts.length) send(message);
};
$('#message').onkeydown = event => {
  if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    if (!$('#composer button[type="submit"]').disabled) $('#composer').requestSubmit();
  }
};
$('#fetch').onclick = () => send('Fetch the Double Agent queue, run preflight, select the highest-value actionable item, and complete it using evidence-backed testing. Ask me in chat for any missing fixture or required approval.', true);
$('#validate-a').onclick = async () => {
  try {
    // Queues Double Agent automated-testing for the current Agent A findings and
    // fetches it, so Agent B claims a work item and can actually test through Burp.
    await api('/api/run/validate-findings', {method: 'POST', body: '{}'});
    await poll();
  } catch (error) {
    showNotice(error.message);
  }
};
const seedDialog = $('#seed-dialog');
$('#seed-surface').onclick = () => {
  const result = $('#seed-result');
  result.className = 'connection-test-result hidden';
  result.textContent = '';
  seedDialog.showModal();
};
$('#close-seed').onclick = $('#cancel-seed').onclick = () => seedDialog.close();
seedDialog.addEventListener('cancel', event => { event.preventDefault(); seedDialog.close(); });
$('#seed-form').onsubmit = async event => {
  event.preventDefault();
  const text = event.target.elements.namedItem('text').value.trim();
  if (!text) return;
  const result = $('#seed-result');
  const button = event.target.querySelector('[type="submit"]');
  result.className = 'connection-test-result testing';
  result.textContent = 'Parsing seed source…';
  button.disabled = true;
  try {
    const value = await api('/api/seed', {method: 'POST', body: JSON.stringify({text})});
    result.className = 'connection-test-result success';
    result.textContent = `Added ${value.new_routes} new of ${value.routes} ${value.kind} route(s) to coverage${value.applied ? '' : ' — will apply on the next discovery pass'}.`;
    event.target.elements.namedItem('text').value = '';
    await poll();
  } catch (error) {
    result.className = 'connection-test-result failure';
    result.textContent = error.message;
  } finally {
    button.disabled = false;
  }
};

const stopRunDialog = $('#stop-run-dialog');
$('#stop').onclick = () => stopRunDialog.showModal();
$('#cancel-stop-run').onclick = () => stopRunDialog.close();
stopRunDialog.addEventListener('cancel', event => {
  event.preventDefault();
  stopRunDialog.close();
});
$('#confirm-stop-run').onclick = async () => {
  stopRunDialog.close();
  const stopButton = $('#stop');
  stopButton.disabled = true;
  stopButton.textContent = 'Waiting for model to stop…';
  $('#run-state').textContent = 'Waiting for model to stop…';
  try {
    await api('/api/run/stop', {method: 'POST', body: '{}'});
    await poll();
  } catch (error) {
    stopButton.disabled = false;
    stopButton.textContent = 'Stop current run';
    showNotice(error.message);
  }
};
$('#bootstrap').onclick = async () => {
  $('#bootstrap').disabled = true;
  try {
    await api('/api/connect/burp', {method: 'POST', body: '{}'});
    await poll();
  } catch (error) {
    $('#bootstrap').disabled = false;
    showNotice(error.message);
  }
};
async function clearConversation() {
  try {
    await api('/api/run/clear', {method: 'POST', body: '{}'});
    attachmentDrafts = []; renderAttachments(); composerStatus('');
    conversationScroll = 0; followConversation = true;
      cache = {messages: [], modelStream: '', modelRun: 0};
    renderedFeed = null;
    last = 0;
    await poll();
  } catch (error) {
    showNotice(error.message);
  }
}

const newConversationDialog = $('#new-conversation-dialog');
$('#clear').onclick = () => newConversationDialog.showModal();
$('#cancel-new-conversation').onclick = () => newConversationDialog.close();
$('#confirm-new-conversation').onclick = async () => {
  newConversationDialog.close();
  await clearConversation();
};

const dialog = $('#settings-dialog');
function clearConnectionTestResult() {
  const result = $('#connection-test-result');
  result.className = 'connection-test-result hidden';
  result.textContent = '';
}

function renderModelDescription() {
  const selected = $('#model-choice').value;
  const option = modelOption(selected);
  const provider = providerOptions.find(item => item.id === (option?.provider || 'openai_compatible'));
  const recNote = option?.recommended_max_steps
    ? ` · recommended budget: ${option.recommended_max_steps} steps / ${option.recommended_max_output_tokens} output tokens`
    : '';
  const hasConnection = Boolean(selected);
  $('#empty-connections').classList.toggle('hidden', hasConnection);
  $('#active-connection-row').classList.toggle('hidden', !hasConnection);
  $('#connection-summary').classList.toggle('hidden', !hasConnection);
  $('#resolved-endpoint-row').classList.toggle('hidden', !hasConnection);
  $('#model-description').textContent = (option?.description || 'Local OpenAI-compatible connection.') + recNote;
  $('#provider-badge').textContent = option?.provider_label || provider?.label || 'Local';
  $('#connection-title').textContent = option?.model || selected;
  const isBedrock = option?.provider === 'bedrock' || selected === 'bedrock';
  $('#bedrock-settings').classList.toggle('hidden', !isBedrock);
  // The model-ID field is only needed for the custom Bedrock option (no fixed id).
  const needsModelId = isBedrock && !(option && option.model_id);
  $('#bedrock-model-row').classList.toggle('hidden', !needsModelId);
  // Custom model URLs are editable in the model dialog.
  const urlField = $('#model-url-input');
  urlField.disabled = true;
  const region = option?.region || $('#settings-form').elements.namedItem('bedrock_region').value || 'us-east-1';
  urlField.value = isBedrock ? `https://bedrock-runtime.${region}.amazonaws.com` : (option?.url || loadedModelUrl);
  $('#legacy-model-settings').classList.toggle('hidden', !hasConnection || Boolean(option?.custom) || isBedrock);
  // Remove is only available for user-added custom models.
  const active = ['starting', 'running', 'waiting', 'stopping'].includes(latestState.status);
  $('#test-model').disabled = active || !hasConnection || pendingActions.has('connection-test');
  $('#remove-model').disabled = active || !option?.custom || pendingActions.has('remove-model');
  $('#edit-model').disabled = active || !option?.custom;
}

let connectionTestRequest = 0;
function clearConnectionTestResult() {
  connectionTestRequest += 1;
  const result = $('#connection-test-result');
  result.className = 'connection-test-result hidden';
  result.textContent = '';
}

function renderSkillOptions(selectedIds = []) {
  const selected = new Set(selectedIds);
  const container = $('#skill-options');
  container.innerHTML = skillCatalog.map(skill => `
    <label class="skill-option">
      <input type="checkbox" name="selected_skill" value="${esc(skill.id)}" ${selected.has(skill.id) ? 'checked' : ''}>
      <span><strong>${esc(skill.name)}</strong><small>${esc(skill.description)}</small></span>
      <em>${skill.builtin ? 'Built in' : 'Custom'}</em>
    </label>`).join('');
}

async function openSettings(section = settingsSection) {
  $('#settings-status').classList.add('hidden');
  $('#settings-form').querySelectorAll('input[type="password"]').forEach(input => { input.value = ''; });
  const [value, catalog] = await Promise.all([api('/api/settings'), api('/api/skills')]);
  modelOptions = value.model_options || [];
  providerOptions = value.providers || [];
  loadedModelUrl = value.model_url || '';
  skillCatalog = catalog.skills || [];
  const select = $('#model-choice');
  const options = [...modelOptions];
  if (value.model && !options.some(option => option.id === value.model)) {
    options.push({id: value.model, label: `${value.model} (custom)`, description: 'Custom model served by the configured API.'});
  }
  select.innerHTML = options.map(option => `<option value="${esc(option.id)}">${esc(option.label)}</option>`).join('');
  $('#bedrock-model-list').innerHTML = (value.bedrock_model_suggestions || []).map(id => `<option value="${esc(id)}"></option>`).join('');
  for (const element of $('#settings-form').elements) {
    if (element.name && element.name !== 'selected_skill' && value[element.name] != null) element.value = value[element.name];
  }
  select.value = value.model;
  $('#legacy-model-url').value = value.model_url || '';
  renderSkillOptions(value.selected_skills || []);
  renderModelDescription();
  clearConnectionTestResult();
  selectSettings(section);
  dialog.showModal();
  if (section === 'models' && !modelOptions.length) $('#add-model').focus();
}
const helpDialog = $('#help-dialog');
$('#help').onclick = () => { closeNavigation(); helpDialog.showModal(); };
$('#close-help').onclick = $('#done-help').onclick = () => helpDialog.close();
$('#settings').onclick = () => { closeNavigation(); openSettings().catch(error => showNotice(error.message)); };
$('#setup-connection').onclick = () => openSettings('models').then(() => { if (!modelOptions.length) openModelDialog(); }).catch(error => showNotice(error.message));
// Switching model applies that model's recommended step/output budget so hosted
// models get room for long runs without manual tuning. The user can still edit
// the fields before saving; the saved values then win over the recommendation.
function applyRecommendedLimits(modelId) {
  const option = modelOption(modelId);
  const form = $('#settings-form');
  if (option?.recommended_max_steps) form.elements.namedItem('max_steps').value = option.recommended_max_steps;
  if (option?.recommended_max_output_tokens) form.elements.namedItem('max_output_tokens').value = option.recommended_max_output_tokens;
}
$('#model-choice').onchange = () => {
  renderModelDescription();
  clearConnectionTestResult();
  applyRecommendedLimits($('#model-choice').value);
};
function closeSettings() {
  $('#settings-form').querySelectorAll('input[type="password"]').forEach(input => { input.value = ''; });
  dialog.close();
}
$('#close-settings').onclick = $('#cancel-settings').onclick = closeSettings;
dialog.addEventListener('cancel', () => { $('#settings-form').querySelectorAll('input[type="password"]').forEach(input => { input.value = ''; }); });
$('#settings-form').addEventListener('invalid', event => {
  const pane = event.target.closest('.settings-pane');
  if (pane) selectSettings(pane.id.replace('settings-', ''));
}, true);
$('#settings-form').onsubmit = async event => {
  event.preventDefault();
  const body = {};
  for (const [key, value] of new FormData(event.target).entries()) {
    if (key === 'selected_skill') continue;
    if (value !== '' || (!key.includes('token') && !key.includes('key'))) {
      body[key] = ['max_steps', 'max_output_tokens'].includes(key) ? Number(value) : value;
    }
  }
  body.model_url = $('#legacy-model-url').value;
  delete body.legacy_model_url;
  body.selected_skills = [...event.target.querySelectorAll('input[name="selected_skill"]:checked')].map(input => input.value);
  try {
    await api('/api/settings', {method: 'POST', body: JSON.stringify(body)});
    dialog.close();
    composerStatus('Settings saved.');
    poll();
  } catch (error) {
    $('#settings-status').textContent = error.message;
    $('#settings-status').classList.remove('hidden');
  }
};

const skillDialog = $('#skill-dialog');
let pendingSkillSelection = [];

function checkedSkillIds() {
  return [...$('#skill-options').querySelectorAll('input:checked')].map(input => input.value);
}

function returnToSettings() {
  if (skillDialog.open) skillDialog.close();
  renderSkillOptions(pendingSkillSelection);
  dialog.showModal();
}

$('#add-skill').onclick = () => {
  // WebKit does not reliably expose one modal dialog on top of another. Keep the
  // unsaved selection, close Settings, then restore it when this editor closes.
  pendingSkillSelection = checkedSkillIds();
  dialog.close();
  $('#skill-status').classList.add('hidden');
  skillDialog.showModal();
};
$('#close-skill').onclick = $('#cancel-skill').onclick = returnToSettings;
skillDialog.addEventListener('cancel', event => {
  event.preventDefault();
  returnToSettings();
});
$('#skill-form').onsubmit = async event => {
  event.preventDefault();
  const body = Object.fromEntries(new FormData(event.target).entries());
  try {
    const result = await api('/api/skills', {method: 'POST', body: JSON.stringify(body)});
    const catalog = await api('/api/skills');
    skillCatalog = catalog.skills || [];
    pendingSkillSelection = [...new Set([...pendingSkillSelection, result.skill.id])];
    event.target.reset();
    returnToSettings();
  } catch (error) {
    $('#skill-status').textContent = error.message;
    $('#skill-status').classList.remove('hidden');
  }
};

// Custom model management.
const modelDialog = $('#model-dialog');
let editingModelId = null;
let editingModel = null;
let modelCatalogRequest = 0;

function resetModelCatalog() {
  modelCatalogRequest += 1;
  const isBedrock = selectedProvider().id === 'bedrock';
  $('#connection-catalog').classList.toggle('hidden', isBedrock);
  $('#load-models').disabled = isBedrock;
  $('#load-models').textContent = 'Load models';
  $('#model-catalog-status').className = 'hint hidden';
  $('#model-catalog-status').textContent = '';
  $('#server-models-row').classList.add('hidden');
  $('#server-models').innerHTML = '<option value="">Choose a model…</option>';
  $('#connection-model-list').innerHTML = isBedrock ? ($('#bedrock-model-list').innerHTML || '') : '';
}

function selectedProvider() {
  return providerOptions.find(item => item.id === $('#connection-provider').value) || providerOptions[0] || {};
}

function renderProviderFields(setDefaultUrl = false) {
  const provider = selectedProvider();
  const isBedrock = provider.id === 'bedrock';
  const isLocal = provider.id === 'openai_compatible';
  $('#provider-description').textContent = provider.description || '';
  $('#connection-url-row').classList.toggle('hidden', isBedrock);
  $('#connection-region-row').classList.toggle('hidden', !isBedrock);
  $('#connection-thinking-row').classList.toggle('hidden', !isLocal);
  $('#connection-thinking-help').classList.toggle('hidden', !isLocal);
  $('#connection-key-label').textContent = provider.key_label || 'API key';
  const reusesSavedKey = editingModel?.api_key_set && provider.id === (editingModel.provider || 'openai_compatible');
  $('#connection-api-key').placeholder = reusesSavedKey
    ? 'Saved — leave blank to keep it'
    : (provider.key_placeholder || '');
  $('#connection-api-key').required = !isLocal && !reusesSavedKey;
  if (setDefaultUrl && !isBedrock) $('#model-form').elements.namedItem('url').value = provider.default_url || '';
  if (setDefaultUrl && isBedrock && !$('#model-form').elements.namedItem('region').value) {
    $('#model-form').elements.namedItem('region').value = 'us-east-1';
  }
  const modelPlaceholders = {
    openrouter: 'Exact OpenRouter ID: provider/model',
    openai: 'Example: gpt-5.6-sol',
    anthropic: 'Example: claude-sonnet-4-6',
    bedrock: 'Example: global.anthropic.claude-sonnet-4-6',
    openai_compatible: 'Exact ID returned by /models',
  };
  $('#connection-model').placeholder = modelPlaceholders[provider.id] || 'Exact model ID';
  resetModelCatalog();
  $('#model-status').className = 'form-status hidden';
  $('#model-status').textContent = '';
}

function openModelDialog(option = null) {
  editingModelId = option?.id || null;
  editingModel = option;
  const form = $('#model-form');
  form.reset();
  const providerSelect = $('#connection-provider');
  providerSelect.innerHTML = providerOptions.map(provider => `<option value="${esc(provider.id)}">${esc(provider.label)}</option>`).join('');
  providerSelect.value = option?.provider || 'openai_compatible';
  form.elements.namedItem('supports_thinking').checked = Boolean(option?.supports_thinking);
  form.elements.namedItem('supports_images').checked = Boolean(option?.supports_images);
  for (const name of ['label', 'model', 'url', 'region']) {
    form.elements.namedItem(name).value = option?.[name] || '';
  }
  renderProviderFields(!option);
  modelDialog.querySelector('h2').textContent = option ? 'Edit connection' : 'Add a connection';
  form.querySelector('[type="submit"]').textContent = option ? 'Save and use' : 'Add and use';
  dialog.close();
  modelDialog.showModal();
}
$('#connection-provider').onchange = () => {
  $('#connection-api-key').value = '';
  renderProviderFields(true);
};
$('#add-model').onclick = () => openModelDialog();
$('#edit-model').onclick = () => {
  const option = modelOption($('#model-choice').value);
  if (option?.custom) openModelDialog(option);
};
$('#close-model').onclick = $('#cancel-model').onclick = () => { resetModelCatalog(); modelDialog.close(); dialog.showModal(); };
modelDialog.addEventListener('cancel', event => { event.preventDefault(); resetModelCatalog(); modelDialog.close(); dialog.showModal(); });
$('#model-form').elements.namedItem('url').addEventListener('input', resetModelCatalog);
$('#connection-api-key').addEventListener('input', resetModelCatalog);
$('#server-models').onchange = () => {
  if ($('#server-models').value) $('#connection-model').value = $('#server-models').value;
};
$('#connection-model').addEventListener('input', () => { $('#server-models').value = $('#connection-model').value; });
$('#load-models').onclick = async () => {
  const form = $('#model-form');
  const url = form.elements.namedItem('url');
  if (!url.value.trim()) {
    $('#model-catalog-status').className = 'hint catalog-error';
    $('#model-catalog-status').textContent = 'Enter the API base URL before loading models.';
    url.focus();
    return;
  }
  if (!$('#connection-api-key').reportValidity()) return;
  resetModelCatalog();
  const request = modelCatalogRequest;
  const status = $('#model-catalog-status');
  const button = $('#load-models');
  status.className = 'hint';
  status.textContent = 'Loading models from the server…';
  button.disabled = true;
  button.textContent = 'Loading…';
  const body = {provider: $('#connection-provider').value, url: url.value, api_key: $('#connection-api-key').value};
  if (editingModelId) body.id = editingModelId;
  try {
    const value = await api('/api/models/catalog', {method: 'POST', body: JSON.stringify(body)});
    if (request !== modelCatalogRequest || !modelDialog.open) return;
    const models = value.models || [];
    if (!models.length) {
      status.textContent = 'The server returned no model IDs. Check the server or enter an ID manually.';
      return;
    }
    const options = models.map(id => `<option value="${esc(id)}">${esc(id)}</option>`).join('');
    $('#server-models').innerHTML = '<option value="">Choose a model…</option>' + options;
    $('#connection-model-list').innerHTML = options;
    $('#server-models-row').classList.remove('hidden');
    if (!$('#connection-model').value.trim() && models.length === 1) $('#connection-model').value = models[0];
    $('#server-models').value = $('#connection-model').value;
    status.textContent = `${models.length} model${models.length === 1 ? '' : 's'} loaded${value.truncated ? ' · showing the first 1,000' : ''}. Choose one below or enter an ID manually.`;
    $('#server-models').focus();
  } catch (error) {
    if (request !== modelCatalogRequest || !modelDialog.open) return;
    status.className = 'hint catalog-error';
    status.textContent = error.message;
  } finally {
    if (request === modelCatalogRequest) { button.disabled = false; button.textContent = 'Load models'; }
  }
};
$('#model-form').onsubmit = async event => {
  event.preventDefault();
  const body = Object.fromEntries(new FormData(event.target).entries());
  body.supports_thinking = event.target.elements.namedItem('supports_thinking').checked;
  body.supports_images = event.target.elements.namedItem('supports_images').checked;
  try {
    if (editingModelId) body.id = editingModelId;
    await api(editingModelId ? '/api/models/edit' : '/api/models', {method: 'POST', body: JSON.stringify(body)});
    resetModelCatalog();
    event.target.reset();
    modelDialog.close();
    await openSettings();
  } catch (error) {
    $('#model-status').className = 'form-status failure';
    $('#model-status').textContent = error.message;
  }
};
$('#test-model').onclick = async () => {
  const id = $('#model-choice').value;
  if (!id) return;
  const request = ++connectionTestRequest;
  const result = $('#connection-test-result');
  const button = $('#test-model');
  result.className = 'connection-test-result testing';
  result.textContent = 'Testing credentials, endpoint, and model…';
  button.disabled = true;
  try {
    const value = await api('/api/models/test', {method: 'POST', body: JSON.stringify({id})});
    if (request !== connectionTestRequest || id !== $('#model-choice').value) return;
    result.className = 'connection-test-result success';
    result.textContent = `Connected · ${value.detail}`;
  } catch (error) {
    if (request !== connectionTestRequest || id !== $('#model-choice').value) return;
    result.className = 'connection-test-result failure';
    result.textContent = error.message;
  } finally {
    const active = ['starting', 'running', 'waiting', 'stopping'].includes(latestState.status);
    button.disabled = active || !$('#model-choice').value;
  }
};
$('#remove-model').onclick = async () => {
  const id = $('#model-choice').value;
  const option = modelOption(id);
  if (!option?.custom) return;
  if (!confirm(`Remove connection "${option.label || id}" and its saved API key from this Mac?`)) return;
  try {
    await api('/api/models/delete', {method: 'POST', body: JSON.stringify({id})});
    await openSettings();
  } catch (error) {
    showNotice(error.message);
  }
};
// Keep asynchronous actions locked across the periodic state refresh.
for (const [selector, event, key] of [
  ['#bootstrap', 'onclick', 'bootstrap'], ['#validate-a', 'onclick', 'validate'],
  ['#confirm-new-conversation', 'onclick', 'clear'], ['#test-model', 'onclick', 'connection-test'],
  ['#remove-model', 'onclick', 'remove-model'], ['#settings-form', 'onsubmit', 'settings'],
  ['#model-form', 'onsubmit', 'model-save'], ['#skill-form', 'onsubmit', 'skill-save'],
  ['#seed-form', 'onsubmit', 'seed']
]) {
  const element = $(selector);
  element[event] = lockAction(key, element[event], element.matches('form') ? element.querySelector('[type="submit"]') : element);
}
poll();
setInterval(poll, 500);
