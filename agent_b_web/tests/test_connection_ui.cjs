const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const script = fs.readFileSync(require.resolve('../static/app.js'), 'utf8');
const functions = script.slice(script.indexOf('function connectionChoices('), script.indexOf('const seedDialog ='));
const page = fs.readFileSync(require.resolve('../static/index.html'), 'utf8');
assert.doesNotMatch(page, /id="validate-a"/);
assert.doesNotMatch(script, /\$\('#validate-a'\)/);
assert.doesNotMatch(script, /latestState\.discussion_mode|thinking: null, discussion|>Discuss<|Discuss something else/);

function fixture(overrides = {}) {
  const calls = [];
  const message = {id: 42, role: 'assistant', metadata: {connection_offer: true}};
  const context = {
    esc: String, cache: {messages: [message]}, dismissedConnectionOffers: new Set(),
    pendingActions: new Set(), harnessOnline: true, sending: false, uploading: false, attachmentDrafts: [],
    latestState: {status: 'idle', burp_prompt_loaded: true, settings: {model: 'fixture'}, notebook: {snapshot: {status: 'ready'}}},
    api: async (...args) => { calls.push(args); }, poll: async () => {}, render: () => {},
    showNotice: text => calls.push(['notice', text]), $: () => ({focus: () => calls.push(['focus'])}),
    ...overrides,
  };
  vm.createContext(context); vm.runInContext(functions, context);
  return {context, calls, message};
}

(async () => {
  let {context, calls, message} = fixture();
  assert.match(context.connectionChoices(message, 42), /Verify findings/);
  assert.match(context.connectionChoices(message, 42), /Give another task/);
  assert.equal(context.connectionChoices(message, 43), '');
  assert.equal(context.connectionChoices({...message, metadata: {}}, 42), '');
  await context.chooseConnectionAction('message', '42');
  assert.deepEqual(calls, [['focus']]); // Discussion starts no assessment or model call.
  assert.ok(context.dismissedConnectionOffers.has('42'));

  ({context, calls} = fixture());
  await context.chooseConnectionAction('verify', '42');
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], '/api/run/validate-findings');
  assert.equal(calls[0][1].method, 'POST');
  await context.chooseConnectionAction('verify', '42');
  assert.equal(calls.length, 1); // A consumed choice cannot start another run.

  for (const change of [
    c => { c.latestState.status = 'running'; },
    c => { c.latestState.pending_question = {id: 'approval-fixture'}; },
    c => { c.latestState.burp_prompt_loaded = false; },
    c => { c.latestState.notebook.snapshot.status = 'target_changed'; },
    c => { c.cache.messages.push({id: 43, role: 'user'}); },
    c => { c.harnessOnline = false; },
    c => { c.pendingActions.add('validate'); },
  ]) {
    ({context, calls} = fixture()); change(context);
    await context.chooseConnectionAction('verify', '42');
    assert.equal(calls.length, 0);
  }

  ({context, calls} = fixture());
  context.latestState.settings.model = '';
  await context.chooseConnectionAction('verify', '42');
  assert.equal(calls[0][0], 'notice');
  assert.doesNotMatch(JSON.stringify(calls), /\/api\//);

  ({context, calls} = fixture({api: async () => { throw new Error('fixture unavailable'); }}));
  await context.chooseConnectionAction('verify', '42');
  assert.equal(calls[0][0], 'notice');
  assert.equal(context.pendingActions.size, 0);
  assert.equal(context.dismissedConnectionOffers.size, 0); // Failed requests remain retryable.
  console.log('PASS: connection choices route explicit verification; chat accepts directions; stale/duplicate/blocked choices cannot run; sidebar validation button removed');
})().catch(error => { console.error(error); process.exitCode = 1; });
