// The passkey pages' script: the standard `navigator.credentials.create` and
// `.get` calls, with the base64url conversions WebAuthn needs on either side
// of them. Nothing here decides anything: the server mints, the server
// verifies, the server records. The link token rides every call so the server
// knows the page was opened from a link the kernel's endpoint minted.
'use strict';

const b64u = {
  decode(s) {
    const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  },
  encode(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
};

function token() {
  return new URLSearchParams(location.search).get('t') || '';
}

function say(text, kind) {
  const el = document.getElementById('status');
  el.textContent = text;
  el.className = kind || '';
}

async function post(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  let j = null;
  try { j = await r.json(); } catch (e) { j = null; }
  if (!r.ok) throw new Error((j && j.error) || ('HTTP ' + r.status));
  return j;
}

async function enroll() {
  const t = token();
  const button = document.getElementById('go');
  button.disabled = true;
  try {
    say('Waiting for the authenticator…');
    const started = await post('/enroll/start', { t });
    const pk = started.options.publicKey;
    pk.challenge = b64u.decode(pk.challenge);
    pk.user.id = b64u.decode(pk.user.id);
    (pk.excludeCredentials || []).forEach((c) => { c.id = b64u.decode(c.id); });
    const cred = await navigator.credentials.create({ publicKey: pk });
    const credential = {
      id: cred.id,
      rawId: b64u.encode(cred.rawId),
      type: cred.type,
      response: {
        attestationObject: b64u.encode(cred.response.attestationObject),
        clientDataJSON: b64u.encode(cred.response.clientDataJSON),
        transports: cred.response.getTransports ? cred.response.getTransports() : undefined,
      },
      extensions: cred.getClientExtensionResults(),
    };
    const done = await post('/enroll/finish', { t, state_id: started.state_id, credential });
    say('Enrolled ' + done.device_id + '. You can close this page; `vk passkey ls` lists it.', 'ok');
  } catch (e) {
    say('Not enrolled: ' + (e && e.message ? e.message : e), 'err');
    button.disabled = false;
  }
}

async function approve(taskId) {
  const t = token();
  const button = document.getElementById('go');
  button.disabled = true;
  const base = '/approve/' + encodeURIComponent(taskId);
  try {
    say('Waiting for the authenticator…');
    const started = await post(base + '/start', { t });
    const pk = started.options.publicKey;
    pk.challenge = b64u.decode(pk.challenge);
    (pk.allowCredentials || []).forEach((c) => { c.id = b64u.decode(c.id); });
    const a = await navigator.credentials.get({ publicKey: pk });
    const credential = {
      id: a.id,
      rawId: b64u.encode(a.rawId),
      type: a.type,
      response: {
        authenticatorData: b64u.encode(a.response.authenticatorData),
        clientDataJSON: b64u.encode(a.response.clientDataJSON),
        signature: b64u.encode(a.response.signature),
        userHandle: a.response.userHandle ? b64u.encode(a.response.userHandle) : null,
      },
      extensions: a.getClientExtensionResults(),
    };
    const done = await post(base + '/finish', { t, state_id: started.state_id, credential });
    say('Approved ' + done.subject_hash + ' with ' + done.device_id + '. The task is ' +
        (done.status || 'recorded') + '; you can close this page.', 'ok');
  } catch (e) {
    say('Not approved: ' + (e && e.message ? e.message : e), 'err');
    button.disabled = false;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const go = document.getElementById('go');
  if (!go) return;
  if (!window.PublicKeyCredential) {
    say('This browser has no WebAuthn support; open the link in Edge, Chrome, Firefox or Safari.', 'err');
    go.disabled = true;
    return;
  }
  const task = go.dataset.task;
  go.addEventListener('click', () => (task ? approve(task) : enroll()));
});
