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
let latestState = {};
let questionKey = null;
let suggestionsKey = null;

function composerStatus(text) { $('#composer-status').textContent = text; }

function renderAttachments() {
  const list = $('#attachment-list');
  list.classList.toggle('hidden', !attachmentDrafts.length);
  list.innerHTML = attachmentDrafts.map((f, index) => `<span class="attachment-chip">${f.mime.startsWith('image/') ? `<img class="attachment-thumbnail" src="/api/files/${encodeURIComponent(f.id)}/preview" alt="${esc(f.name)}">` : ''}${esc(f.name)} · ${Math.ceil(f.size / 1024)} KB <button type="button" data-remove-file="${index}" aria-label="Remove ${esc(f.name)}">×</button></span>`).join('');
  list.querySelectorAll('[data-remove-file]').forEach(button => {
    button.onclick = () => { attachmentDrafts.splice(Number(button.dataset.removeFile), 1); renderAttachments(); };
  });
}

async function attachFiles(files) {
  if (uploading || sending) return;
  if (latestState.pending_question || ['starting', 'running', 'waiting', 'stopping'].includes(latestState.status)) {
    composerStatus('Wait for the response or stop the run before attaching files.'); return;
  }
  if (attachmentDrafts.length + files.length > 4) { composerStatus('Attach up to four files per message.'); return; }
  uploading = true;
  $('#attach-files').disabled = true;
  $('#conversation-mode').value = 'discuss';
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
    composerStatus('Files ready. They will be sent to the selected connection with your message.');
  } catch (error) { composerStatus(error.message); }
  finally { uploading = false; $('#attach-files').disabled = false; $('#file-picker').value = ''; }
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

function closeNavigation() {
  document.querySelector('aside').classList.remove('open');
}

$('#open-nav').onclick = () => document.querySelector('aside').classList.add('open');
$('#close-nav').onclick = closeNavigation;

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
  return `${formatted(message.slice(0, 1600))}<details class="full-response"><summary>Read full response · ${message.length.toLocaleString()} characters</summary>${formatted(message)}</details>`;
}

function render(value) {
  latestState = value;
  $('#composer-help').textContent = $('#conversation-mode').value === 'discuss'
    ? `Discuss uses no assessment tools. Text files up to 120 KB; images up to 3 MB. Files go to ${modelOption(value.settings?.model)?.label || 'the selected connection'} when sent. Text is redacted for common secrets; check screenshots yourself.`
    : 'Assessment chat uses the current Burp context. Use Discuss for file and image review.';
  if (value.settings?.model_options) modelOptions = value.settings.model_options;
  const stopping = value.status === 'stopping';
  const bootstrapped = Boolean(value.burp_prompt_loaded);
  $('#run-state').textContent = stopping ? 'Waiting for model to stop…' : value.status;
  $('#step-label').textContent = `Step ${value.step} of ${value.max_steps}`;
  $('#step-meter').style.width = `${Math.min(100, value.step / Math.max(1, value.max_steps) * 100)}%`;
  const findingProgress = value.finding_validation_progress || {};
  const findingProgressEl = $('#finding-progress');
  const linkedFindingCount = Number(findingProgress.linked || 0);
  findingProgressEl.classList.toggle('hidden', linkedFindingCount < 1);
  findingProgressEl.textContent = linkedFindingCount > 0
    ? `${Number(findingProgress.verdicts_recorded || 0)} of ${linkedFindingCount} linked findings dispositioned`
    : '';

  const active = ['starting', 'running', 'waiting', 'stopping'].includes(value.status);
  $('#run-dot').className = `dot ${value.status === 'running' ? 'ok' : active ? 'warn' : ''}`;
  $('#stop').disabled = !active || stopping;
  $('#stop').textContent = stopping ? 'Waiting for model to stop…' : 'Stop current run';
  $('#fetch').disabled = active || !bootstrapped;
  $('#validate-a').disabled = active || !bootstrapped;
  $('#fetch').classList.toggle('primary', bootstrapped);
  $('#bootstrap').disabled = active || bootstrapped;
  $('#bootstrap').classList.toggle('primary', !bootstrapped);
  $('#bootstrap').textContent = bootstrapped ? 'Bootstrap sent' : '1. Send bootstrap';
  $('#bootstrap').title = bootstrapped
    ? 'Bootstrap already sent in this conversation'
    : 'Load the Burp context for this conversation';
  $('#fetch').title = bootstrapped ? 'Fetch the next Double Agent work item' : 'Send bootstrap first';
  $('#validate-a').title = bootstrapped ? 'Validate current Agent A findings' : 'Send bootstrap first';
  const targetKnown = Boolean(value.target_url);
  $('#seed-surface').disabled = active || !bootstrapped || !targetKnown;
  $('#seed-surface').title = !bootstrapped ? 'Send bootstrap first'
    : !targetKnown ? 'Fetch a target first so seed routes resolve'
    : 'Add OpenAPI/sitemap/URL routes to coverage and discovery';
  const bootstrapGuidance = $('#bootstrap-guidance');
  bootstrapGuidance.textContent = bootstrapped
    ? 'Bootstrap loaded for this conversation. Burp controls are ready.'
    : 'For Burp work, start here. Regular chat works without it.';
  bootstrapGuidance.classList.toggle('ready', bootstrapped);
  $('#thinking-control').classList.toggle('hidden', !modelOption(value.settings.model)?.supports_thinking || value.burp_prompt_loaded);
  $('#thinking-choice').disabled = active;
  const activeSkills = value.active_skills || [];
  $('#active-skills').innerHTML = activeSkills.length
    ? activeSkills.map(skill => `<span title="${esc(skill.description)}">${esc(skill.name)}</span>`).join('')
    : '<span class="muted-skill">None · comparison control</span>';

  const doubleAgent = value.health.double_agent;
  dot($('#burp-dot'), doubleAgent.ok);
  $('#burp-state').textContent = doubleAgent.ok ? 'Connected on 8777' : String(doubleAgent.detail || 'Unavailable').slice(0, 70);
  const model = value.health.model;
  dot($('#model-dot'), model.ok);
  $('#model-name').textContent = modelOption(value.settings.model)?.label || value.settings.model;
  $('#model-state').textContent = model.ok ? `${value.settings.model} ready` : String(model.detail || 'Unavailable').slice(0, 70);
  const targetUrl = value.target_url || '';
  $('#target-row').classList.toggle('hidden', !targetUrl);
  $('#target-link-main').classList.toggle('hidden', !targetUrl);
  if (targetUrl) {
    $('#target-link').href = targetUrl;
    $('#target-link').textContent = targetUrl;
    $('#target-link').title = `Open ${targetUrl} in your browser`;
    $('#target-link-main').href = targetUrl;
    $('#target-link-main').textContent = `Open target · ${targetUrl}`;
    $('#target-link-main').title = `Open ${targetUrl} in your browser`;
  }
  $('#live').textContent = active ? 'Live run' : 'Local and idle';
  const streamPanel = $('#model-stream-panel');
  const streamDelta = value.model_stream || '';
  const streamOffset = Number(value.model_stream_offset || 0);
  const streamLength = Number(value.model_stream_length || 0);
  const runChanged = cache.modelRun !== value.started;
  if (runChanged) {
    cache.modelRun = value.started;
    cache.modelStream = '';
    if (active && value.started) streamPanel.open = true;
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
  const modelElapsed = active && value.model_stream_started
    ? Math.max(0, Math.floor(Date.now() / 1000 - Number(value.model_stream_started)))
    : 0;
  const reasoningMode = value.model_reasoning_mode || 'provider output shown verbatim';
  const streamChannel = String(value.model_stream_channel || '');
  let activityLabel = 'Model activity';
  if (active) {
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
  $('#model-activity-label').textContent = activityLabel;
  $('#model-activity-dot').className = `activity-dot ${active ? 'active' : streamLength ? 'complete' : ''}`;
  $('#model-stream-source').textContent = value.model_reasoning_seen
    ? 'Provider-exposed reasoning'
    : value.model_reasoning_requested
      ? 'Waiting for provider reasoning'
      : 'Action commentary';
  streamPanel.classList.toggle('active', active);
  streamPanel.classList.toggle('has-reasoning', Boolean(value.model_reasoning_seen));
  $('#model-stream-state').textContent = streamLength
    ? `Step ${value.model_stream_step}${modelElapsed ? ` · ${modelElapsed}s` : ''} · ${reasoningMode}`
    : `Waiting for ${modelOption(value.settings.model)?.label || 'model'} · ${reasoningMode}`;

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

  // Operator chat shows the user's messages, the model's small "thinking"
  // lines, its questions, and final results — but not the big per-step
  // narration bubbles or progress chatter.
  const transcript = cache.messages.filter(message => {
    if (message.role !== 'assistant') return true;
    const m = message.metadata || {};
    return !(m.intermediate || m.progress);
  });
  const feedKey = transcript.map(message => `message:${message.id}`).join('|');
  const timeline = $('#timeline');

  if (feedKey !== renderedFeed) {
    const position = timeline.scrollTop;
    const follow = timeline.scrollHeight - position - timeline.clientHeight < 80;
    const items = transcript.map(message => {
      const meta = message.metadata || {};
      const harnessMessage = message.role === 'assistant' && (meta.progress || meta.connection || meta.harness_status);
      const thinking = message.role === 'assistant' && meta.thinking;
      const speaker = message.role === 'user' ? 'You' : harnessMessage ? 'Harness status' : thinking ? 'Thinking' : 'Agent B';
      const content = message.role === 'assistant'
        ? String(message.content ?? '').replace(/^(?:[\t ]*\r?\n)+/, '')
        : message.content;
      return `
      <div class="message ${esc(message.role)} ${harnessMessage ? 'harness-status' : ''} ${thinking ? 'thinking' : ''}">
        <div class="meta">${speaker}</div>
        <div class="bubble">${visibleMessage(content)}${(meta.attachments || []).map(f => `<a class="attachment-download" href="/api/files/${encodeURIComponent(f.id)}" download>${f.mime.startsWith('image/') ? `<img class="attachment-thumbnail" src="/api/files/${encodeURIComponent(f.id)}/preview" alt="${esc(f.name)}">` : ''}${esc(f.name)} ↓</a>`).join('')}</div>
        ${message.role === 'assistant' && !harnessMessage ? `<a class="download-link response-download" href="/api/messages/${encodeURIComponent(message.id)}/download" download>Download response</a>` : ''}
      </div>`;
    });

    timeline.innerHTML = items.length ? items.join('') : `
      <div class="empty"><div><strong>Agent B is ready</strong>Regular chat is ready. For Burp work, send bootstrap first.</div></div>`;
    timeline.scrollTop = follow ? timeline.scrollHeight : position;
    renderedFeed = feedKey;
  }

  const pending = value.pending_question;
  const question = $('#question');
  if (pending && questionKey !== pending.id) {
    questionKey = pending.id;
    question.classList.remove('hidden');
    const approval = pending.id.startsWith('approval-');
    question.innerHTML = `<div class="eyebrow">${approval ? 'YOUR APPROVAL IS REQUIRED' : 'A QUESTION FOR YOU'}</div><strong>${esc(pending.question)}</strong><p>${esc(pending.reason)}</p><div>${
      (pending.options || []).map(option => `<button data-answer="${esc(option)}">${esc(option)}</button>`).join('')
    }</div>${approval ? '<p class="hint">Approval applies only to this pending action. Stopping the run cancels it.</p>' : '<form id="question-reply"><input aria-label="Your answer" name="reply" maxlength="4000" required placeholder="Or answer in your own words…"><button type="submit">Reply</button></form>'}`;
    question.querySelectorAll('button').forEach(button => {
      button.onclick = () => answer(pending.id, button.dataset.answer);
    });
    if (!approval) $('#question-reply').onsubmit = event => { event.preventDefault(); answer(pending.id, event.target.elements.reply.value); };
  } else if (!pending) {
    questionKey = null;
    question.classList.add('hidden');
  }
  renderSuggestions(value.route_recommendations || []);
}

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
      const s = items.find(item => item.id === button.dataset.discuss);
      $('#conversation-mode').value = 'discuss';
      $('#message').value = `Let's discuss this recommendation and its uncertainty:\n${s.subject || ''}\n${s.rationale || ''}\nSuggested next step: ${s.next_step || ''}`;
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
    render(await api(`/api/state?after=${last}&stream_after=${cache.modelStream.length}`));
  } catch (error) {
    $('#live').textContent = 'Harness offline';
  } finally {
    busy = false;
  }
}

async function send(message, assessment = false) {
  if (sending || uploading) return;
  sending = true;
  $('#composer button[type="submit"]').disabled = true;
  try {
    const mode = $('#thinking-control').classList.contains('hidden') ? 'auto' : $('#thinking-choice').value;
    await api('/api/chat', {method: 'POST', body: JSON.stringify({message, thinking: mode === 'auto' ? null : mode === 'on', discussion: !assessment && $('#conversation-mode').value === 'discuss', attachments: assessment ? [] : attachmentDrafts.map(f => f.id)})});
    $('#message').value = '';
    if (!assessment) { attachmentDrafts = []; renderAttachments(); }
    composerStatus('Message sent.');
    await poll();
  } catch (error) {
    composerStatus(error.message);
  } finally {
    sending = false;
    $('#composer button[type="submit"]').disabled = false;
  }
}

async function answer(id, response) {
  $('#question').querySelectorAll('button,input').forEach(el => { el.disabled = true; });
  try {
    await api(`/api/questions/${id}/answer`, {method: 'POST', body: JSON.stringify({answer: response})});
    await poll();
  } catch (error) {
    composerStatus(error.message);
    $('#question').querySelectorAll('button,input').forEach(el => { el.disabled = false; });
  }
}

$('#composer').onsubmit = event => {
  event.preventDefault();
  const message = $('#message').value.trim();
  if (message || attachmentDrafts.length) send(message);
};
$('#message').onkeydown = event => {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    $('#composer').requestSubmit();
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
    alert(error.message);
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
    alert(error.message);
  }
};
$('#bootstrap').onclick = async () => {
  $('#bootstrap').disabled = true;
  try {
    await api('/api/connect/burp', {method: 'POST', body: '{}'});
    await poll();
  } catch (error) {
    $('#bootstrap').disabled = false;
    alert(error.message);
  }
};
async function clearConversation() {
  try {
    await api('/api/run/clear', {method: 'POST', body: '{}'});
    attachmentDrafts = []; renderAttachments(); composerStatus('');
    cache = {messages: [], modelStream: '', modelRun: 0};
    renderedFeed = null;
    last = 0;
    await poll();
  } catch (error) {
    alert(error.message);
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
function renderModelDescription() {
  const selected = $('#model-choice').value;
  const option = modelOption(selected);
  const provider = providerOptions.find(item => item.id === (option?.provider || 'openai_compatible'));
  const recNote = option?.recommended_max_steps
    ? ` · recommended budget: ${option.recommended_max_steps} steps / ${option.recommended_max_output_tokens} output tokens`
    : '';
  $('#model-description').textContent = (option?.description || 'Built-in local OpenAI-compatible connection.') + recNote;
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
  $('#legacy-model-settings').classList.toggle('hidden', Boolean(option?.custom) || isBedrock);
  // Remove is only available for user-added custom models.
  $('#remove-model').disabled = !option?.custom;
  $('#edit-model').disabled = !option?.custom;
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

async function openSettings() {
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
  dialog.showModal();
}
$('#settings').onclick = () => { closeNavigation(); openSettings(); };
// Switching model applies that model's recommended step/output budget so hosted
// models get room for long runs without manual tuning. The user can still edit
// the fields before saving; the saved values then win over the recommendation.
function applyRecommendedLimits(modelId) {
  const option = modelOption(modelId);
  const form = $('#settings-form');
  if (option?.recommended_max_steps) form.elements.namedItem('max_steps').value = option.recommended_max_steps;
  if (option?.recommended_max_output_tokens) form.elements.namedItem('max_output_tokens').value = option.recommended_max_output_tokens;
}
$('#model-choice').onchange = () => { renderModelDescription(); applyRecommendedLimits($('#model-choice').value); };
$('#close-settings').onclick = $('#cancel-settings').onclick = () => dialog.close();
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
    poll();
  } catch (error) {
    alert(error.message);
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
    alert(error.message);
  }
};

// Custom model management.
const modelDialog = $('#model-dialog');
let editingModelId = null;
let editingModel = null;

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
    openai: 'Example: gpt-5.6-sol',
    anthropic: 'Example: claude-sonnet-4-6',
    bedrock: 'Example: global.anthropic.claude-sonnet-4-6',
    openai_compatible: 'Exact ID returned by /models',
  };
  $('#connection-model').placeholder = modelPlaceholders[provider.id] || 'Exact model ID';
  const suggestions = isBedrock ? ($('#bedrock-model-list').innerHTML || '') : '';
  $('#connection-model-list').innerHTML = suggestions;
  $('#connection-test-result').className = 'connection-test-result hidden';
  $('#connection-test-result').textContent = '';
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
$('#connection-provider').onchange = () => renderProviderFields(true);
$('#add-model').onclick = () => openModelDialog();
$('#edit-model').onclick = () => {
  const option = modelOption($('#model-choice').value);
  if (option?.custom) openModelDialog(option);
};
$('#close-model').onclick = $('#cancel-model').onclick = () => { modelDialog.close(); dialog.showModal(); };
modelDialog.addEventListener('cancel', event => { event.preventDefault(); modelDialog.close(); dialog.showModal(); });
$('#model-form').onsubmit = async event => {
  event.preventDefault();
  const body = Object.fromEntries(new FormData(event.target).entries());
  body.supports_thinking = event.target.elements.namedItem('supports_thinking').checked;
  body.supports_images = event.target.elements.namedItem('supports_images').checked;
  try {
    if (editingModelId) body.id = editingModelId;
    await api(editingModelId ? '/api/models/edit' : '/api/models', {method: 'POST', body: JSON.stringify(body)});
    event.target.reset();
    modelDialog.close();
    await openSettings();
  } catch (error) {
    alert(error.message);
  }
};
$('#test-model').onclick = async () => {
  const form = $('#model-form');
  if (!form.reportValidity()) return;
  const body = Object.fromEntries(new FormData(form).entries());
  body.supports_thinking = form.elements.namedItem('supports_thinking').checked;
  if (editingModelId) body.id = editingModelId;
  const result = $('#connection-test-result');
  const button = $('#test-model');
  result.className = 'connection-test-result testing';
  result.textContent = 'Testing credentials, endpoint, and model…';
  button.disabled = true;
  try {
    const value = await api('/api/models/test', {method: 'POST', body: JSON.stringify(body)});
    result.className = 'connection-test-result success';
    result.textContent = `Connected · ${value.detail}`;
  } catch (error) {
    result.className = 'connection-test-result failure';
    result.textContent = error.message;
  } finally {
    button.disabled = false;
  }
};
$('#remove-model').onclick = async () => {
  const id = $('#model-choice').value;
  const option = modelOption(id);
  if (!option?.custom) return;
  if (!confirm(`Remove custom model "${option.label || id}"?`)) return;
  try {
    await api('/api/models/delete', {method: 'POST', body: JSON.stringify({id})});
    await openSettings();
  } catch (error) {
    alert(error.message);
  }
};

poll();
setInterval(poll, 500);
