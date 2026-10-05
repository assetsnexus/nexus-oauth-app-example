const out = document.getElementById('out');

function show(value) {
  out.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}

async function api(path, options) {
  const res = await fetch(path, { credentials: 'same-origin', ...options });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(body.error || res.statusText), { status: res.status, body });
  return body;
}

document.getElementById('login-user').onclick = () => {
  window.location.href = '/api/login?subjectType=user';
};

document.getElementById('login-org').onclick = () => {
  const orgId = document.getElementById('org-id').value.trim();
  window.location.href = `/api/login?subjectType=org_member&orgId=${encodeURIComponent(orgId)}`;
};

document.getElementById('refresh').onclick = async () => {
  try {
    const [identities, status, fields] = await Promise.all([
      api('/api/identities'),
      api('/api/status'),
      api('/api/fields'),
    ]);
    show({ identities, status, fields });
  } catch (err) {
    show(err.body || err.message);
  }
};

document.getElementById('subscription').onclick = async () => {
  try {
    show(await api('/api/subscription'));
  } catch (err) {
    show(err.body || err.message);
  }
};

document.getElementById('request-phone').onclick = async () => {
  try {
    show(await api('/api/fields', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fields: [{ field: 'phone', purpose: 'Account recovery' }] }),
    }));
  } catch (err) {
    show(err.body || err.message);
  }
};

document.getElementById('request-batch').onclick = async () => {
  try {
    const result = await api('/api/permissions/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        items: [{ kind: 'command', commandName: 'anx.crm.project.list' }],
      }),
    });
    show(result);
    if (result.approvalUrl) window.open(result.approvalUrl, '_blank', 'noopener');
  } catch (err) {
    show(err.body || err.message);
  }
};
