import { createViewerNonce } from "../auth.js";
import { VERSION } from "../version.js";

/**
 * CSP for the login shell. Mirrors the viewer's policy but drops the
 * localhost connect-src entries — the login page only ever talks back to
 * its own origin. `form-action 'none'` is intentional: the form is
 * submitted via fetch so the password never lands in a navigation.
 */
export function buildLoginCsp(nonce: string): string {
  return [
    "default-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "form-action 'none'",
    `script-src 'nonce-${nonce}'`,
    "script-src-attr 'none'",
    "style-src 'unsafe-inline'",
    "connect-src 'self'",
    "img-src 'self'",
    "font-src 'self'",
  ].join("; ");
}

export function renderLoginPage(options: { notice?: string } = {}): {
  html: string;
  csp: string;
} {
  const nonce = createViewerNonce();
  const notice = options.notice
    ? `<p class="notice" role="status">${escapeHtml(options.notice)}</p>`
    : "";

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="robots" content="noindex, nofollow" />
<title>agentmemory dashboard</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml" />
<style>
  :root {
    color-scheme: light dark;
    --bg: #fbfbfa; --card: #ffffff; --ink: #1a1a1a; --muted: #6b6b6b;
    --line: #e3e3e0; --accent: #1a1a1a; --accent-ink: #ffffff; --danger: #b3261e;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #141414; --card: #1c1c1c; --ink: #f0efec; --muted: #9a9a95;
      --line: #2e2e2e; --accent: #f0efec; --accent-ink: #141414; --danger: #f2b8b5;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px;
    background: var(--bg); color: var(--ink);
    font-family: ui-sans-serif, -apple-system, "Segoe UI", Roboto, sans-serif;
  }
  .card {
    width: 100%; max-width: 380px; background: var(--card);
    border: 1px solid var(--line); border-radius: 12px; padding: 28px;
  }
  h1 { margin: 0 0 4px; font-size: 17px; letter-spacing: -0.01em; }
  .sub { margin: 0 0 20px; font-size: 13px; color: var(--muted); line-height: 1.5; }
  label { display: block; font-size: 12px; font-weight: 600; margin-bottom: 6px; }
  input {
    width: 100%; padding: 10px 12px; font-size: 14px; color: var(--ink);
    background: var(--bg); border: 1px solid var(--line); border-radius: 8px;
  }
  input:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
  button {
    width: 100%; margin-top: 14px; padding: 10px 12px; font-size: 14px; font-weight: 600;
    color: var(--accent-ink); background: var(--accent);
    border: 0; border-radius: 8px; cursor: pointer;
  }
  button[disabled] { opacity: 0.55; cursor: default; }
  .msg { margin-top: 12px; font-size: 12.5px; line-height: 1.5; color: var(--danger); min-height: 1em; }
  .notice { margin: 0 0 16px; font-size: 12.5px; color: var(--muted); line-height: 1.5; }
  .foot { margin-top: 18px; font-size: 11px; color: var(--muted); text-align: center; }
</style>
</head>
<body>
  <main class="card">
    <h1>agentmemory</h1>
    <p class="sub">Enter the dashboard password to continue.</p>
    ${notice}
    <form id="login-form" autocomplete="off">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password"
             spellcheck="false" required aria-describedby="msg" />
      <button id="submit" type="submit">Unlock</button>
    </form>
    <p id="msg" class="msg" role="alert" aria-live="polite"></p>
    <p class="foot">agentmemory v${escapeHtml(VERSION)}</p>
  </main>
<script nonce="${nonce}">
(function () {
  // Derive sibling endpoints from the current path so the page works
  // whether it is mounted at /dashboard/view or /agentmemory/dashboard/view.
  var base = window.location.pathname.replace(/\\/view\\/?$/, '');
  var form = document.getElementById('login-form');
  var input = document.getElementById('password');
  var button = document.getElementById('submit');
  var msg = document.getElementById('msg');

  input.focus();

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var value = input.value;
    if (!value) return;
    msg.textContent = '';
    button.disabled = true;
    button.textContent = 'Checking...';

    fetch(base + '/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ password: value })
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        return { status: res.status, data: data };
      });
    }).then(function (r) {
      if (r.status === 200) {
        // Full reload so the server re-renders /view, this time with the
        // session cookie present, and hands back the real viewer.
        window.location.replace(base + '/view');
        return;
      }
      input.value = '';
      button.disabled = false;
      button.textContent = 'Unlock';
      if (r.status === 429) {
        msg.textContent = (r.data && r.data.error) || 'Too many attempts. Try again later.';
      } else if (r.status === 503) {
        msg.textContent = (r.data && r.data.error) || 'Dashboard is not configured.';
      } else {
        msg.textContent = 'Incorrect password.';
      }
      input.focus();
    }).catch(function () {
      button.disabled = false;
      button.textContent = 'Unlock';
      msg.textContent = 'Network error. Please try again.';
    });
  });
})();
</script>
</body>
</html>`;

  return { html, csp: buildLoginCsp(nonce) };
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
