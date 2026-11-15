#!/usr/bin/env node
// Deterministic failure injection and real local bash session transactions.
const assert = require('assert/strict');
const { EventEmitter } = require('events');
const { PassThrough } = require('stream');
const { spawn, spawnSync, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createRuntime } = require('../src/runtime');
const { createExecutor } = require('../src/exec');
const { createSessions } = require('../src/session');
const { makeExecCommand, killProcessGroup, stripAnsi, readFrom } = require('../src/ssh');
function locateBash() {
  if (process.env.SSH_BRIDGE_TEST_BASH) return process.env.SSH_BRIDGE_TEST_BASH;
  if (process.platform !== 'win32') return 'bash';
  try { return execFileSync('where.exe', ['bash'], { encoding: 'utf8' }).trim().split(/\r?\n/).find((p) => !p.includes('WindowsApps')); }
  catch (_) { return undefined; }
}
const bash = locateBash();
const shq = (s) => "'" + s.replace(/'/g, "'\\''") + "'";
const clients = [];
function fixture({ exec, poolSize = 1, channelsPerConnection = 1, host = {}, configFile = __filename, connect } = {}) {
  const runtime = createRuntime({ cfg: { poolSize, channelsPerConnection }, configFile,
    realClient: false, algorithms: {}, resolveHost: (name) => ({ name, host: name, port: 22, user: 'u', ...host }), verify: () => ({ ok: true }),
    clientFactory() {
      const c = new EventEmitter(); clients.push(c);
      c.connect = (opts) => connect ? connect(c, opts) : setImmediate(() => c.emit('ready'));
      c.end = () => { if (!c.ended) { c.ended = true; c.emit('close'); } };
      c.exec = (cmd, opts, cb) => exec(c, cmd, cb);
      return c;
    },
  });
  return runtime;
}
function channel() {
  const ch = new EventEmitter();
  ch.stderr = new PassThrough();
  ch.stdin = new PassThrough();
  ch.close = () => { ch.closed = true; ch.emit('close'); };
  ch.signal = (_s, cb) => cb?.();
  return ch;
}
function executor(runtime, graceMs = 10) {
  return createExecutor({ runtime, makeExecCommand, killProcessGroup, shq, stripAnsi, maxOutput: 1024, graceMs });
}
let passed = 0;
async function test(name, fn) { await fn(); passed++; console.log('  PASS ' + name); }
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
async function main() {
  await test('key/agent/password authentication order and relative key path are explicit', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-bridge-auth-'));
    fs.writeFileSync(path.join(dir, 'key'), 'dummy-fixture-key');
    const r = fixture({ configFile: path.join(dir, 'fixture.json'),
      host: { privateKeyPath: 'key', passphrase: 'fixture-only', agent: 'fixture-agent', password: 'fixture-password' },
      connect(c, opts) {
        assert.deepEqual(opts.authHandler, ['none', 'publickey', 'agent', 'password']);
        assert.equal(opts.privateKey.toString(), 'dummy-fixture-key'); assert.equal(opts.passphrase, 'fixture-only');
        assert.equal(opts.agentForward, false); assert.equal(opts.keepaliveInterval, 15000);
        setImmediate(() => c.emit('ready'));
      },
    });
    try { await r.operation({}, async () => (await r.acquire('a')).release()); }
    finally { r.shutdown(); fs.rmSync(dir, { recursive: true, force: true }); }
  });
  await test('unreadable private key rejects without retaining a handshake timer', async () => {
    const r = fixture({ host: { privateKeyPath: '/missing-ssh-bridge-test-key' } });
    await assert.rejects(r.operation({}, () => r.acquire('a')), { code: 'ENOENT' }); r.shutdown();
  });
  await test('shutdown cancels a pending handshake and disposes its client', async () => {
    let client; const r = fixture({ connect(c) { client = c; } });
    const p = r.operation({}, () => r.acquire('a'));
    await delay(0); r.shutdown(); await assert.rejects(p, { code: 'CLOSED' }); assert.equal(client.ended, true);
  });
  await test('host capacity is isolated and queue deadline removes waiter', async () => {
    const r = fixture();
    let held;
    await r.operation({}, async () => { held = await r.acquire('a'); });
    await r.operation({ timeoutMs: 30 }, async () => { const b = await r.acquire('b'); b.release(); });
    await assert.rejects(r.operation({ timeoutMs: 15 }, () => r.acquire('a')), { code: 'TIMEOUT' });
    held.release();
    await r.operation({ timeoutMs: 30 }, async () => (await r.acquire('a')).release());
    r.shutdown();
  });
  await test('cancelled queued operation never reserves capacity', async () => {
    const r = fixture(); let lease;
    await r.operation({}, async () => { lease = await r.acquire('a'); });
    const c = new AbortController();
    const p = r.operation({ signal: c.signal }, () => r.acquire('a'));
    c.abort(); await assert.rejects(p, { code: 'CANCELLED' }); lease.release();
    await r.operation({ timeoutMs: 30 }, async () => (await r.acquire('a')).release()); r.shutdown();
  });
  await test('post-dispatch close preserves output and never replays', async () => {
    let count = 0;
    const r = fixture({ exec(_c, _cmd, cb) { count++; const ch = channel(); cb(null, ch); setImmediate(() => { ch.emit('data', Buffer.from('mutation done')); ch.emit('close'); }); } });
    const result = await r.operation({}, () => executor(r).run('a', { command: 'mutate' }));
    assert.equal(count, 1); assert.equal(result.outcome, 'unknown'); assert.equal(result.stdout, 'mutation done'); r.shutdown();
  });
  await test('hung exec-open times out and late channel is closed', async () => {
    let complete;
    const r = fixture({ exec(_c, _cmd, cb) { complete = cb; } });
    const result = await r.operation({ timeoutMs: 15 }, () => executor(r).run('a', { command: 'true' }));
    assert.equal(result.timedOut, true); assert.equal(result.outcome, 'unknown');
    const ch = channel(); complete(null, ch); assert.equal(ch.closed, true); r.shutdown();
  });
  await test('one failed connection does not close a healthy sibling', async () => {
    const r = fixture({ poolSize: 2 }); let a, b;
    await r.operation({}, async () => { a = await r.acquire('a'); b = await r.acquire('a'); });
    r.invalidate(a.entry); assert.equal(b.entry.closing, false); a.release(); b.release(); r.shutdown();
  });
  await test('UTF8 across exec chunks and truthful truncation', async () => {
    const r = fixture({ exec(_c, _cmd, cb) {
      const ch = channel(); cb(null, ch);
      setImmediate(() => { const b = Buffer.from('中文'); for (const byte of b) ch.emit('data', Buffer.from([byte])); ch.emit('exit', 7); ch.emit('close', 7); });
    } });
    const result = await r.operation({}, () => executor(r).run('a', { command: 'false' }));
    assert.equal(result.stdout, '中文'); assert.equal(result.exitCode, 7); r.shutdown();
  });
  await test('exit without close closes actual channel before reusing slot', async () => {
    let ch;
    const r = fixture({ exec(_c, _cmd, cb) { ch = channel(); cb(null, ch); setImmediate(() => ch.emit('exit', 0)); } });
    await r.operation({}, () => executor(r).run('a', { command: 'true' }));
    assert.equal(ch.closed, true); r.shutdown();
  });
  await test('short SFTP packets and zero-size pseudo files read until EOF', async () => {
    for (const reported of [0, 100000]) {
      const data = Buffer.from('中'.repeat(30000)); let closed = 0;
      const s = { open: (_f, _m, cb) => cb(null, 1), close: (_h, cb) => { closed++; cb(); },
        fstat: (_h, cb) => cb(null, { size: reported }),
        read(_h, b, off, len, pos, cb) { const piece = data.subarray(pos, pos + Math.min(len, 1024)); piece.copy(b, off); cb(null, piece.length); } };
      const result = await readFrom(s, '/file', 0, 100000);
      assert.equal(result.content, data.toString()); assert.equal(result.error, null); assert.equal(closed, 1);
    }
  });
  await test('session timeout preserves partial output and synchronous close keeps transport healthy', async () => {
    let client;
    const r = fixture({ exec(c, _cmd, cb) {
      client = c; const ch = channel(); ch.write = () => ch.emit('data', Buffer.from('partial'));
      cb(null, ch);
    } });
    const sessions = createSessions({ runtime: r, shq, maxOutput: 1024 });
    try {
      const result = await r.operation({ timeoutMs: 30 }, () => sessions.run('a', { command: 'hang' }));
      assert.equal(result.timedOut, true); assert.equal(result.stdout, 'partial'); assert.equal(result.outcome, 'unknown');
      await delay(280); assert.notEqual(client.ended, true);
    } finally { sessions.shutdown(); r.shutdown(); }
  });
  await test('queued session timeout never bypasses the active transaction or dispatches later', async () => {
    const writes = [];
    const r = fixture({ exec(_c, _cmd, cb) {
      const ch = channel(); ch.write = line => {
        writes.push(line);
        const token = /133;D;([a-f0-9]+);/.exec(line)[1];
        setTimeout(() => ch.emit('data', Buffer.from(`\x1b]133;D;${token};0\x07`)), writes.length === 1 ? 80 : 0);
      }; cb(null, ch);
    } });
    const sessions = createSessions({ runtime: r, shq, maxOutput: 1024 });
    const run = (command, timeoutMs) => r.operation({ timeoutMs }, () => sessions.run('a', { command }));
    try {
      const first = run('first', 1000);
      await delay(0);
      await assert.rejects(run('cancelled', 10), { code: 'TIMEOUT' });
      const third = run('third', 1000); assert.equal(writes.length, 1);
      await Promise.all([first, third]); assert.equal(writes.length, 2); assert.match(writes[1], /third/);
    } finally { sessions.shutdown(); r.shutdown(); }
  });
  await test('transport loss while opening persistent shell rejects without waiting for deadline', async () => {
    const r = fixture({ exec(c) { setImmediate(() => c.emit('close')); } });
    const sessions = createSessions({ runtime: r, shq, maxOutput: 1024 });
    try {
      await assert.rejects(r.operation({ timeoutMs: 1000 }, () => sessions.run('a', { command: 'true' })), { code: 'CONNECTION_CLOSED' });
    } finally { sessions.shutdown(); r.shutdown(); }
  });
  if (!bash || spawnSync(bash, ['--version'], { stdio: 'ignore' }).status !== 0) {
    console.log('SKIP real bash transaction test: install bash or set SSH_BRIDGE_TEST_BASH');
  } else await test('real persistent bash: concurrent multiline, cwd/env, limits, close/reopen', async () => {
    const children = new Set();
    const r = fixture({ channelsPerConnection: 2, exec(c, cmd, cb) {
      const child = spawn(bash, ['--noprofile', '--norc', '-c', cmd], { stdio: 'pipe' }); children.add(child);
      const ch = new EventEmitter(); ch.stdin = child.stdin; ch.stderr = child.stderr; ch.write = (...a) => child.stdin.write(...a);
      child.stdout.on('data', (d) => ch.emit('data', d));
      child.on('error', (e) => ch.emit('error', e));
      child.on('close', (code) => { children.delete(child); ch.emit('close', code); });
      ch.close = () => { child.stdin.end(); child.kill(); };
      c.once('close', ch.close); cb(null, ch);
    } });
    const sessions = createSessions({ runtime: r, shq, maxOutput: 1024 });
    const run = (args) => r.operation({ timeoutMs: 3000 }, () => sessions.run('a', args));
    try {
      let result = await run({ command: 'echo first\nfalse' }); assert.equal(result.exitCode, 1); assert.equal(result.stdout.trim(), 'first');
      const results = await Promise.all([run({ command: 'export X=good\nprintf A' }), run({ command: 'printf "$X"' })]);
      assert.equal(results[0].stdout, 'A'); assert.equal(results[1].stdout, 'good');
      result = await run({ cwd: '/tmp', env: { Y: '中文' }, pipefail: true, command: 'printf "$Y"; pwd; false | true' });
      assert.equal(result.exitCode, 1); assert.ok(result.stdout.startsWith('中文'));
      result = await run({ command: "printf '%02000d' 1" }); assert.equal(result.truncated, true); assert.equal(result.stdout.length, 1024);
      await assert.rejects(run({ input: '', command: 'cat' }), { code: 'UNSUPPORTED_OPTIONS' });
      sessions.close('a'); result = await run({ command: 'printf reset' }); assert.equal(result.stdout, 'reset');
      result = await run({ command: 'printf partial; exit 0' }); assert.equal(result.outcome, 'unknown'); assert.equal(result.stdout, 'partial');
      result = await run({ command: 'printf recreated' }); assert.match(result.warning, /previous cwd\/env\/functions\/aliases are gone/);
      result = await run({ command: 'true' }); assert.equal(result.warning, undefined);
    } finally { sessions.shutdown(); r.shutdown(); for (const c of children) c.kill(); }
  });
  console.log(`Runtime checks: ${passed} passed`);
}
main().catch((e) => { console.error(e); process.exitCode = 1; });
