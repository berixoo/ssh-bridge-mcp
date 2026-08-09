const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveHost } = require('../src/config');

test('resolveHost uses default when name omitted', () => {
  const cfg = { default: 'b', hosts: { a: { host: '1', user: 'u' }, b: { host: '2', user: 'u' } } };
  assert.equal(resolveHost(cfg).name, 'b');
});

test('resolveHost falls back to first host without default', () => {
  const cfg = { hosts: { a: { host: '1', user: 'u' } } };
  assert.equal(resolveHost(cfg).name, 'a');
});

test('resolveHost throws on unknown host', () => {
  const cfg = { hosts: { a: { host: '1', user: 'u' } } };
  assert.throws(() => resolveHost(cfg, 'nope'), /unknown host/);
});

test('sudoPassword falls back to password', () => {
  const cfg = { hosts: { a: { host: '1', user: 'u', password: 'p' } } };
  assert.equal(resolveHost(cfg, 'a').sudoPassword, 'p');
});
