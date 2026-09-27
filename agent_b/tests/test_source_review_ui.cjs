const assert = require('node:assert/strict');
const {offerFor} = require('../static/source-review.js');
const message = (content, metadata={}) => ({id: 1, role:'assistant', content, metadata});
assert.equal(offerFor(message('This may affect demo 1.2.3; check the advisory.')), true);
assert.equal(offerFor(message('Check CVE-2024-3094 applicability before concluding.')), true);
assert.equal(offerFor(message('Hello. What are we looking at?')), false);
assert.equal(offerFor(message('The current app version is 3.1.0.')), false);
assert.equal(offerFor(message('A vulnerability needs evidence, not assumptions.')), false);
assert.equal(offerFor({...message('Outdated package 1.2.3'), role:'user'}), false);
for (const flag of ['thinking','intermediate','progress','harness_status','connection']) {
  assert.equal(offerFor(message('Affected package 1.2.3', {[flag]:true})), false);
}
console.log('PASS: passive review offers, no DOM or network required');
