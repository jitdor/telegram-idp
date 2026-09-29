// Polls the auth request status and follows the redirect the server computed.
// Loaded as an external script so the page can run under a strict CSP.
(function () {
  var root = document.getElementById('login');
  var statusEl = document.getElementById('status');
  var statusUrl = root.getAttribute('data-status-url');
  var stopped = false;

  function setStatus(text) {
    statusEl.textContent = text;
  }

  async function poll() {
    if (stopped) return;
    try {
      var res = await fetch(statusUrl, { credentials: 'same-origin', cache: 'no-store' });
      if (res.status === 429) return;
      if (!res.ok) {
        stopped = true;
        setStatus('This sign-in request is no longer valid. Please start again.');
        return;
      }
      var data = await res.json();
      if (data.status === 'approved' || data.status === 'denied') {
        stopped = true;
        setStatus(data.status === 'approved' ? 'Approved! Redirecting…' : 'Sign-in was denied. Redirecting…');
        window.location.assign(data.redirect_to);
      } else if (data.status === 'expired') {
        stopped = true;
        setStatus('This sign-in request expired. Please start again.');
      }
    } catch (e) {
      // Network hiccup: keep polling.
    }
  }

  setInterval(poll, 2000);
})();
