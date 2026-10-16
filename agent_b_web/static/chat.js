/* Markdown from models and captured evidence is untrusted. Keep all rendering
   local, escape raw HTML, restrict navigation and sanitize the final markup. */
(() => {
  const escape = value => String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);

  function safeLink(value) {
    const href = String(value || '').trim();
    if (/^\/api\/files\/[a-zA-Z0-9_-]+(?:\/preview)?$/.test(href)) return href;
    if (!/^https?:\/\//i.test(href)) return null;
    try {
      const url = new URL(href);
      return ['http:', 'https:'].includes(url.protocol) ? url.href : null;
    } catch (_) { return null; }
  }

  const base = window.marked ? new window.marked.Renderer() : null;
  const parser = window.marked ? new window.marked.Marked({
    gfm: true, breaks: false, async: false,
    renderer: {
      html({text}) { return escape(text); },
      link({href, title, tokens, text, autolink}) {
        const label = autolink ? escape(text) : this.parser.parseInline(tokens || []);
        const url = safeLink(href);
        return url ? `<a href="${escape(url)}" target="_blank" rel="noopener noreferrer"${title ? ` title="${escape(title)}"` : ''}>${label}</a>` : label;
      },
      image({href, text, title}) {
        // Only existing local attachments may load pixels automatically.
        const url = safeLink(href);
        if (url && /^\/api\/files\/.+\/preview$/.test(url)) {
          return `<img class="chat-image" src="${escape(url)}" alt="${escape(text || 'Attached image')}" loading="lazy">`;
        }
        const label = escape(text || title || 'Image');
        return url ? `<a href="${escape(url)}" target="_blank" rel="noopener noreferrer">${label}</a>` : label;
      },
      code(token) {
        const label = (token.lang || '').trim().split(/\s+/)[0] || 'Code';
        return `<div class="chat-code"><div class="chat-code-label">${escape(label)}</div>${base.code.call(this, token)}</div>`;
      },
      table(token) {
        return `<div class="chat-table" role="region" aria-label="Table" tabindex="0">${base.table.call(this, token)}</div>`;
      },
    },
  }) : null;

  function render(value, {markdown = true} = {}) {
    const text = String(value ?? '');
    if (!markdown || !parser || !window.DOMPurify?.isSupported) {
      return `<div class="chat-plain">${escape(text)}</div>`;
    }
    try {
      const html = window.DOMPurify.sanitize(parser.parse(text), {
        ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'del', 'a', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
          'ul', 'ol', 'li', 'pre', 'code', 'blockquote', 'hr', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
          'div', 'span', 'input', 'img'],
        ALLOWED_ATTR: ['href', 'title', 'target', 'rel', 'start', 'checked', 'disabled', 'type',
          'class', 'src', 'alt', 'loading', 'role', 'aria-label', 'tabindex'],
        ALLOW_DATA_ATTR: false, SANITIZE_NAMED_PROPS: true,
      });
      return `<div class="chat-markdown">${html}</div>`;
    } catch (_) {
      return `<div class="chat-plain">${escape(text)}</div>`;
    }
  }
  window.AgentBChat = Object.freeze({render});
})();
