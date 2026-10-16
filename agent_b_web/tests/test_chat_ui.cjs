const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const crypto = require('node:crypto');
const root = path.join(__dirname, '../static');
const marked = require('../static/vendor/marked.umd.js');
const script = fs.readFileSync(path.join(root, 'chat.js'), 'utf8');
const page = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
let policy;
// This identity sanitizer isolates our Markdown renderer's own protections.
// The real DOMPurify sanitizer is checked with malicious fixtures in browser QA.
const window = {marked, DOMPurify: {isSupported: true, sanitize(html, options) { policy = options; return html; }}};
vm.runInNewContext(script, {window, URL});
const render = (value, options) => window.AgentBChat.render(value, options);

let html = render('Installed **v3.3.2**.\n\n- Active workers\n- **Aggregate TPS**\n  - Actual server usage\n\n1. Review\n2. Verify\n\n## Next step\n\nUse `GET /account` and *compare* the response.');
assert.match(html, /<strong>v3.3.2<\/strong>/);
assert.match(html, /<ul>[\s\S]*<ul>/);
assert.match(html, /<ol>/);
assert.match(html, /<h2>Next step<\/h2>/);
assert.match(html, /<code>GET \/account<\/code>/);
assert.match(html, /<em>compare<\/em>/);

html = render('```http\nGET /account HTTP/1.1\nHost: example.test\n\n<script>alert(1)</script>\n```\n\n| Finding | Status |\n| --- | --- |\n| #3 | Verified |\n\n> Original evidence\n\n- [x] Reviewed\n- [ ] Follow up');
assert.match(html, /class="chat-code-label">http<\/div>/);
assert.match(html, /GET \/account HTTP\/1.1\nHost: example.test/);
assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
assert.match(html, /class="chat-table" role="region" aria-label="Table" tabindex="0"/);
assert.match(html, /<td>#3<\/td>/);
assert.match(html, /<blockquote>/);
assert.match(html, /<input checked="" disabled="" type="checkbox">/);

html = render('[Docs](https://example.test/docs?q=one&b=two "Reference")\n\nhttps://example.test/path\n\n<https://example.test/other>\n\n[Local file](/api/files/test-file)');
assert.equal((html.match(/target="_blank" rel="noopener noreferrer"/g) || []).length, 4);
assert.match(html, /href="https:\/\/example.test\/docs\?q=one&amp;b=two"/);
assert.match(html, /href="\/api\/files\/test-file"/);
assert.match(html, /title="Reference"/);

for (const input of [
  '[Bad](javascript:alert%281%29)', '[Bad](JaVaScRiPt:alert%281%29)',
  '[Bad](data:text/html;base64,PHNjcmlwdD4=)', '[Bad](javascript&#58;alert%281%29)',
  '[Bad](//external.test/pixel)', '[Bad](/api/run/stop)', '[Bad](file:///etc/passwd)',
  '<img src="https://external.test/pixel" onerror="alert(1)">',
  '<svg><script>alert(1)</script></svg>', '<iframe src="https://external.test"></iframe>',
  '<a href="javascript:alert(1)">Bad</a>', '<style>body{display:none}</style>',
  '<form action="https://external.test"><input name="cookie"></form>',
]) {
  html = render(input);
  assert.doesNotMatch(html, /<(?:script|style|iframe|form|svg|img|a)\b/i, input);
  assert.doesNotMatch(html, /<[^>]+\bon\w+\s*=/i, input);
}
html = render('![Remote image](https://external.test/pixel.png)\n\n![Local image](/api/files/test-file/preview)\n\n![Data](data:image/png;base64,abcd)');
assert.equal((html.match(/<img /g) || []).length, 1);
assert.match(html, /src="\/api\/files\/test-file\/preview"/);
assert.match(html, />Remote image<\/a>/);
assert.doesNotMatch(html, /src="(?:https:|data:)/);

html = render('## A user draft\n\n<script>never run</script>', {markdown: false});
assert.match(html, /class="chat-plain">## A user draft/);
assert.doesNotMatch(html, /<h2>|<script>/);
assert.match(render('Last line.\n\n'.repeat(500) + 'END OF ANSWER'), /END OF ANSWER<\/p>/);
assert.doesNotMatch(render('Long answer. '.repeat(300)), /full-response|Read full response|<details/);
assert.equal(policy.ALLOW_DATA_ATTR, false);
assert.ok(!policy.ALLOWED_TAGS.includes('script') && !policy.ALLOWED_ATTR.includes('style'));

window.DOMPurify.isSupported = false;
assert.match(render('**fallback** <script>'), /class="chat-plain">\*\*fallback\*\* &lt;script&gt;/);
window.DOMPurify.isSupported = true;
window.DOMPurify.sanitize = () => { throw new Error('Unavailable'); };
assert.match(render('**fallback** <script>'), /class="chat-plain">\*\*fallback\*\* &lt;script&gt;/);
assert.ok(page.indexOf('/vendor/marked.umd.js') < page.indexOf('/chat.js'));
assert.ok(page.indexOf('/vendor/purify.min.js') < page.indexOf('/chat.js'));
assert.ok(page.indexOf('/chat.js') < page.indexOf('/app.js'));
assert.match(app, /visibleMessage\(content, message.role === 'assistant'\)/);

for (const dependency of JSON.parse(fs.readFileSync(path.join(root, 'vendor/manifest.json')))) {
  for (const [name, hash] of Object.entries(dependency.files)) {
    assert.equal(crypto.createHash('sha256').update(fs.readFileSync(path.join(root, 'vendor', name))).digest('hex'), hash);
  }
}
console.log('PASS: Markdown structure, code/table formatting, full replies, safe links, no automatic external images, renderer escaping, fallback and pinned dependency integrity');
