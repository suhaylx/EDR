import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isSafeLabBrowserOrigin } from '../.test-dist/security-origin.js';

test('lab login permits HTTPS or localhost/SSH tunnel only', () => {
  for (const [scheme,host] of [
    ['https:', 'edr.turansec.uz'],
    ['https:', '89.126.221.102'],
    ['http:', 'localhost'],
    ['http:', '127.0.0.1'],
    ['http:', '[::1]'],
    ['http:', '::1']
  ]) assert.equal(isSafeLabBrowserOrigin(scheme,host),true,scheme+' '+host);
});

test('lab login fails closed on public HTTP and unsafe schemes', () => {
  for (const [scheme,host] of [
    ['http:', '89.126.221.102'],
    ['http:', 'edr.turansec.uz'],
    ['http:', '192.168.1.20'],
    ['http:', 'localhost.attacker.test'],
    ['http:', '127.0.0.2'],
    ['file:', ''],
    ['data:', ''],
    ['', 'localhost']
  ]) assert.equal(isSafeLabBrowserOrigin(scheme,host),false,scheme+' '+host);
});
