'use strict';
// Tab-lifetime storage for the LAB shared bearer token only. Never store the
// development token in localStorage or on plain public HTTP origins.
(function (root) {
  const key = 'turansec.edr.lab.session-token.v1';
  function allowedOrigin(location) {
    if (!location) return false;
    const protocol = String(location.protocol || '').toLowerCase();
    const host = String(location.hostname || '').toLowerCase();
    return protocol === 'https:' || (protocol === 'http:' &&
      (host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1'));
  }
  function create(location, storageProvider) {
    const allowed = allowedOrigin(location);
    function read() {
      if (!allowed) return '';
      try {
        const value = storageProvider().getItem(key);
        return typeof value === 'string' && value.length <= 1024 ? value : '';
      } catch (_) { return ''; } // privacy mode/storage blocked
    }
    function save(value) {
      if (!allowed || typeof value !== 'string' || value.length < 16 || value.length > 1024) return false;
      try { storageProvider().setItem(key, value); return true; } catch (_) { return false; }
    }
    function clear() {
      // Even a previously stored token may exist while the current origin is
      // unsafe; clear it whenever sessionStorage access is permitted.
      try { storageProvider().removeItem(key); } catch (_) { /* blocked storage */ }
    }
    return {allowed, read, save, clear};
  }
  const api = {allowedOrigin, create};
  root.TuranSecAuthSession = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
