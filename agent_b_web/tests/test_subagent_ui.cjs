const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require.resolve('../static/app.js'), 'utf8');
const elements = new Map();
const element = selector => {
  if (!elements.has(selector)) elements.set(selector, {value: '', checked: false, innerHTML: '', textContent: '',
    classList: {hidden: false, toggle(name, value) { this[name] = value; }, remove() {}}});
  return elements.get(selector);
};
const context = {$: element, modelOption: id => ({label: 'Spark <' + id + '>'}),
  esc: value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;')};
vm.createContext(context);
vm.runInContext(source.slice(source.indexOf('function renderSubagents('), source.indexOf("$('#help').onclick")), context);
context.renderSubagents({running: true, active: 2, maximum: 4, jobs: [{title: '<img src=x onerror=alert(1)>', connection: 'a', status: 'running'}]});
assert.match(element('#subagent-activity').innerHTML, /&lt;img/);
assert.doesNotMatch(element('#subagent-activity').innerHTML, /<img/);
assert.match(element('#subagent-activity').innerHTML, /Spark &lt;a&gt;/);
assert.equal(element('#model-stream-state').textContent, '2 / 4 subagents working');
assert.equal(element('#team-state').textContent, '2 / 4 subagents working');
assert.equal(element('#team-panel').classList.hidden, false);
context.renderSubagents({running: true, active: 4, maximum: 4, counts: {queued: 2, completed: 6}, jobs: [{id: 8, title: 'Review #8', connection: 'b', status: 'running', phase: 'Reading evidence'}]},
  {requests: 8, active_requests: 2, finished_requests: 6, reported_requests: 6, output_tokens: 2100, model_wall_seconds: 20, aggregate_tps: 105, state: 'measured', actors: {}},
  {status: 'running', settings: {subagents_enabled: true}});
assert.equal(element('#team-tps').textContent, '105.0');
assert.equal(element('#team-counts').textContent, '2 queued · 6 finished');
assert.match(element('#subagent-activity').innerHTML, /Reading evidence/);
assert.match(element('#throughput-basis').textContent, /in-flight calls are excluded/);
context.renderSubagents({}, {requests: 2, finished_requests: 2, reported_requests: 1, missing_usage: 1, state: 'unavailable', aggregate_tps: null}, {status: 'running', settings: {subagents_enabled: true}});
assert.equal(element('#team-tps').textContent, 'Unavailable');
assert.equal(element('#team-state').textContent, 'Lead only · subagents available');
context.renderSubagents({}, {requests: 1, state: 'measured', aggregate_tps: 0});
assert.equal(element('#team-tps').textContent, '0.0');
element('#subagents-enabled').checked = false; context.updateSubagentControls();
assert.equal(element('#subagent-controls').classList.hidden, true);
element('#subagents-enabled').checked = true; context.updateSubagentControls();
assert.equal(element('#subagent-controls').classList.hidden, false);

let saved;
context.FormData = class { entries() { return [['max_subagents', '6'], ['subagents_enabled', 'on'], ['subagent_connection', 'a'], ['subagent_connection', 'b']]; } };
context.api = async (path, request) => { saved = JSON.parse(request.body); };
context.dialog = {close() {}}; context.composerStatus = () => {}; context.poll = () => {};
vm.runInContext(source.slice(source.indexOf("$('#settings-form').onsubmit ="), source.indexOf('const skillDialog')), context);
const event = {preventDefault() {}, target: {querySelectorAll(selector) { return selector.includes('subagent_connection') ? [{value: 'a'}, {value: 'b'}] : []; }}};
(async () => {
  await element('#settings-form').onsubmit(event);
  assert.equal(saved.subagents_enabled, true); assert.equal(saved.max_subagents, 6);
  assert.deepEqual(saved.subagent_connections, ['a', 'b']);
  element('#subagents-enabled').checked = false;
  await element('#settings-form').onsubmit(event);
  assert.equal(saved.subagents_enabled, false);
  assert.deepEqual(saved.subagent_connections, ['a', 'b']);
  console.log('PASS: subagent toggle, connections, visible activity, full-run counts and honest aggregate TPS');
})().catch(error => { console.error(error); process.exitCode = 1; });
