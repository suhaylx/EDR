'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const {allowedOrigin, create} = require('./auth-session.js');

const key = 'turansec.edr.lab.session-token.v1';
const token = 'test_lab_token_0123456789';
const src = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');

function storage() {
  const map = new Map();
  return {
    getItem(k) { return map.has(k) ? map.get(k) : null; },
    setItem(k, v) { map.set(k, v); },
    removeItem(k) { map.delete(k); },
    raw: map,
  };
}
function page(url, sessionStorage, fetchImplementation = () => new Promise(() => {})) {
  const location = new URL(url);
  const elements = new Map();
  function el(id) {
    if (!elements.has(id)) elements.set(id, {
      value: '', textContent: '', className: '', innerHTML: '', checked: false, disabled: false,
      listeners: {}, addEventListener(name, callback) { this.listeners[name] = callback; },
      click() { this.listeners.click?.(); },
      change() { this.listeners.change?.(); },
    });
    return elements.get(id);
  }
  const document = {getElementById: el, querySelectorAll() { return []; }};
  const context = {document, location, sessionStorage, fetch: fetchImplementation, console, URLSearchParams, Date, Map, Set};
  context.globalThis = context;
  context.TuranSecAuthSession = {create};
  vm.runInNewContext(src, context, {filename: 'app.js'});
  return {el, state: () => vm.runInNewContext('({token:state.token, data:state.data})', context)};
}

test('auth script is loaded before dashboard and opt-in is visible', () => {
  assert.ok(html.indexOf('/auth-session.js') < html.indexOf('/app.js'));
  assert.match(html, /id="rememberToken"/);
});
test('only HTTPS or explicit loopback HTTP permits token retention', () => {
  for (const url of ['https://edr.example.test/', 'http://127.0.0.1:18080/', 'http://localhost:18080/', 'http://[::1]:18080/']) {
    assert.equal(allowedOrigin(new URL(url)), true, url);
  }
  for (const url of ['http://89.126.221.102:8080/', 'http://192.168.0.11:8080/', 'file:///tmp/edr.html']) {
    assert.equal(allowedOrigin(new URL(url)), false, url);
  }
});
test('sessionStorage retention is tab-scoped, not localStorage, and explicit logout clears', () => {
  const st = storage();
  const first = page('http://127.0.0.1:18080/', st);
  assert.equal(first.el('rememberToken').checked, true);
  first.el('token').value = token;
  first.el('connect').click();
  assert.equal(first.state().token, token);
  assert.equal(st.raw.get(key), token);
  assert.equal(first.el('token').value, '');
  const reload = page('http://127.0.0.1:18080/', st);
  assert.equal(reload.state().token, token);
  assert.equal(reload.el('connect').textContent, 'Disconnect');
  reload.el('connect').click();
  assert.equal(reload.state().token, '');
  assert.equal(st.raw.has(key), false);
  assert.equal(reload.el('connect').textContent, 'Connect');
  assert.equal(page('http://127.0.0.1:18080/', st).state().token, '');
});
test('unchecked remember option prevents persistence and removes previous token', () => {
  const st = storage();
  const p = page('https://edr.example.test/', st);
  p.el('rememberToken').checked = false;
  p.el('token').value = token;
  p.el('connect').click();
  assert.equal(p.state().token, token);
  assert.equal(st.raw.has(key), false);
  p.el('rememberToken').checked = true;
  p.el('rememberToken').change();
  assert.equal(st.raw.get(key), token);
  p.el('rememberToken').checked = false;
  p.el('rememberToken').change();
  assert.equal(st.raw.has(key), false);
});
test('public plaintext HTTP disables API login and does not restore leaked tokens', () => {
  const st = storage();
  st.raw.set(key, token);
  const p = page('http://89.126.221.102:8080/', st);
  assert.equal(p.el('connect').disabled, true);
  assert.equal(p.el('token').disabled, true);
  assert.equal(p.el('rememberToken').disabled, true);
  assert.equal(p.state().token, '');
  assert.match(p.el('notice').textContent, /Unsafe public HTTP/);
  p.el('token').value = token;
  p.el('connect').click();
  assert.equal(p.state().token, '');
});
test('server HTTP 401 rejects and clears remembered token', async () => {
  const st = storage();
  st.raw.set(key, token);
  const p = page('http://localhost:18080/', st, async () => ({status: 401, ok: false, text: async () => 'unauthorized'}));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(p.state().token, '');
  assert.equal(st.raw.has(key), false);
  assert.equal(p.el('connect').textContent, 'Connect');
  assert.match(p.el('notice').textContent, /HTTP 401/);
});
test('storage failures are nonfatal and never enable an insecure origin', () => {
  const blocked = () => { throw new Error('storage disabled'); };
  const auth = create(new URL('https://edr.example.test/'), blocked);
  assert.equal(auth.read(), '');
  assert.equal(auth.save(token), false);
  assert.doesNotThrow(() => auth.clear());
});
