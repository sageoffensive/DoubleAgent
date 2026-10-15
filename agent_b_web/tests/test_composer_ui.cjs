const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const script = fs.readFileSync(require.resolve('../static/app.js'), 'utf8');
const page = fs.readFileSync(require.resolve('../static/index.html'), 'utf8');
const composer = script.slice(script.indexOf('function updateComposer()'), script.indexOf('function composerStatus('));
const stop = script.slice(script.indexOf('async function stopRun()'), script.indexOf("$('#stop').onclick = stopRun;"));
const form = page.slice(page.indexOf('<form id="composer"'), page.indexOf('</form>', page.indexOf('<form id="composer"')));
assert.match(form, /id="stop" type="button"/);
assert.equal((page.match(/id="stop"/g) || []).length, 1);
assert.doesNotMatch(page, /stop-run-dialog/);

function fixture() {
  const nodes = new Map();
  function element(selector) {
    if (selector === '#composer button[type="submit"]') selector = '#send-message';
    if (!nodes.has(selector)) {
      const classes = new Set();
      nodes.set(selector, {
        value: '', textContent: '', disabled: false, readOnly: false, dataset: {}, style: {}, attributes: {}, scrollHeight: 46,
        classList: {toggle: (name, value) => value ? classes.add(name) : classes.delete(name), contains: name => classes.has(name)},
        setAttribute(name, value) { this.attributes[name] = value; },
        addEventListener() {}, querySelectorAll: () => [],
      });
    }
    return nodes.get(selector);
  }
  const calls = [], notices = [];
  const context = {
    $: element, harnessOnline: true, uploading: false, sending: false, attachmentDrafts: [], pendingActions: new Set(),
    latestState: {status: 'idle', settings: {model: 'fixture'}, scope_enforcement: {enabled: true},
      health: {double_agent: {ok: true, detail: {scope_enforcement: {version: 1, fail_closed: true}}}}},
    modelOption: () => ({label: 'Fixture model', supports_thinking: true}),
    api: async (...args) => { calls.push(args); },
    showNotice: value => notices.push(value),
    poll: async () => { context.latestState.status = 'stopped'; },
  };
  vm.createContext(context); vm.runInContext(composer + stop, context);
  context.updateComposer();
  return {context, element, calls, notices};
}

(async () => {
  let {context, element} = fixture();
  assert.ok(element('#stop').classList.contains('hidden'));
  assert.ok(element('#send-message').disabled);
  element('#message').value = 'A message'; context.updateComposer();
  assert.equal(element('#send-message').disabled, false);
  assert.equal(element('#composer-scope-label').textContent, 'Scope enforced');
  delete context.latestState.health.double_agent.detail.scope_enforcement; context.updateComposer();
  assert.equal(element('#composer-scope-label').textContent, 'Scope unavailable');

  context.latestState.status = 'running'; element('#message').value = ''; context.updateComposer();
  assert.equal(element('#stop').classList.contains('hidden'), false);
  assert.equal(element('#stop').disabled, false);
  assert.ok(element('#send-message').classList.contains('hidden'));
  element('#message').value = 'Keep this draft'; context.updateComposer();
  assert.equal(element('#send-message').classList.contains('hidden'), false);
  assert.equal(element('#send-message').attributes['aria-label'], 'Send guidance');
  assert.equal(element('#composer-model').disabled, true);

  context.latestState.status = 'waiting';
  context.latestState.pending_question = {id: 'approval-internet-fixture'}; context.updateComposer();
  assert.equal(element('#composer').classList.contains('hidden'), false);
  assert.equal(element('#stop').disabled, false);
  assert.equal(element('#message').readOnly, true);
  assert.ok(element('#send-message').disabled);
  assert.ok(element('#send-message').classList.contains('hidden'));
  assert.equal(element('#message').value, 'Keep this draft');

  context.latestState.status = 'idle'; context.latestState.pending_question = null;
  element('#thinking-choice').value = 'off'; context.updateComposer();
  assert.equal(context.thinkingPreference(), false);
  element('#thinking-choice').value = 'on'; assert.equal(context.thinkingPreference(), true);
  context.modelOption = () => ({supports_thinking: false}); context.updateComposer();
  assert.equal(context.thinkingPreference(), null);
  assert.ok(element('#composer-thinking').classList.contains('hidden'));

  let f = fixture(); f.context.latestState.status = 'running'; f.element('#message').value = 'Preserved guidance';
  let finishStop;
  f.context.api = (...args) => { f.calls.push(args); return new Promise(resolve => { finishStop = resolve; }); };
  const pending = f.context.stopRun();
  await f.context.stopRun(); // A second click must not submit another stop.
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0][0], '/api/run/stop');
  assert.equal(f.calls[0][1].method, 'POST');
  assert.equal(f.element('#stop').disabled, true);
  assert.equal(f.element('#message').value, 'Preserved guidance');
  finishStop({ok: true}); await pending;
  assert.equal(f.context.latestState.status, 'stopped');
  assert.ok(f.element('#stop').classList.contains('hidden'));
  assert.equal(f.element('#message').value, 'Preserved guidance');

  f = fixture(); f.context.latestState.status = 'waiting';
  f.context.latestState.pending_question = {id: 'approval-internet-fixture'};
  await f.context.stopRun();
  assert.equal(f.calls[0][0], '/api/run/stop'); // Stop never answers or grants approval.

  f = fixture(); f.context.latestState.status = 'running'; f.element('#message').value = 'Retry draft';
  f.context.api = async () => { throw new Error('Fixture outage'); };
  await f.context.stopRun();
  assert.equal(f.context.latestState.status, 'running');
  assert.equal(f.element('#stop').disabled, false);
  assert.equal(f.element('#message').value, 'Retry draft');
  assert.deepEqual(f.notices, ['Fixture outage']);
  console.log('PASS: composer Stop, steering, approvals, thinking capability, scope status and draft preservation');
})().catch(error => { console.error(error); process.exitCode = 1; });
