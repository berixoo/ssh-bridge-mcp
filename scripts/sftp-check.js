#!/usr/bin/env node
'use strict';

// createBridge-level failure injection only. No config loading, sockets, SSH
// servers, environment credentials, or production monkeypatches are involved.
const assert = require('assert/strict');
const { EventEmitter } = require('events');
const { PassThrough } = require('stream');
const { createBridge } = require('../src/ssh');

let passed = 0;
const failures = [];
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}
async function bounded(promise, ms = 1500) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`test watchdog expired after ${ms}ms`)), ms);
    })]);
  } finally { clearTimeout(timer); }
}
function outcome(promise) {
  return promise.then(value => ({ value }), error => ({ error }));
}
async function test(name, fn) {
  try { await fn(); passed++; console.log(`PASS ${name}`); }
  catch (error) { failures.push({ name, error }); console.error(`FAIL ${name}\n  ${error.stack || error}`); }
}
const directory = [
  { filename: '.', attrs: { mode: 0o040755 } },
  { filename: 'file.txt', attrs: { mode: 0o100644, size: 12, mtime: 1 } },
  { filename: 'subdir', attrs: { mode: 0o040755, size: 0, mtime: 1 } },
];

function session({ data = Buffer.from('hello'), maxChunk = 1024, reportedSize = data.length,
  readdir, stat, open, read, autoClose = true } = {}) {
  const s = new EventEmitter();
  s.calls = { readdir: 0, stat: 0, open: 0, fstat: 0, read: 0, close: 0, end: 0 };
  s.requests = [];
  s.end = () => {
    s.calls.end++;
    if (autoClose && !s.ended) { s.ended = true; s.emit('close'); }
  };
  s.readdir = (p, cb) => {
    s.calls.readdir++; s.requests.push(['readdir', p]);
    if (readdir) return readdir(p, cb);
    queueMicrotask(() => cb(null, directory));
  };
  s.stat = (p, cb) => {
    s.calls.stat++; s.requests.push(['stat', p]);
    if (stat) return stat(p, cb);
    queueMicrotask(() => cb(null, { size: reportedSize, mode: 0o100644 }));
  };
  s.open = (p, flags, cb) => {
    s.calls.open++; s.requests.push(['open', p, flags]);
    if (open) return open(p, flags, cb);
    queueMicrotask(() => cb(null, Buffer.from('handle')));
  };
  s.fstat = (_h, cb) => { s.calls.fstat++; queueMicrotask(() => cb(null, { size: reportedSize, mode: 0o100644 })); };
  s.read = (h, buffer, offset, length, position, cb) => {
    s.calls.read++;
    if (read) return read(h, buffer, offset, length, position, cb);
    const chunk = data.subarray(position, position + Math.min(maxChunk, length));
    chunk.copy(buffer, offset);
    queueMicrotask(() => cb(null, chunk.length));
  };
  s.close = (_h, cb) => { s.calls.close++; queueMicrotask(() => cb(null)); };
  return s;
}

function channel() {
  const ch = new EventEmitter();
  ch.stdin = new PassThrough();
  ch.stderr = new PassThrough();
  ch.closeCalls = 0;
  ch.close = () => {
    ch.closeCalls++;
    if (!ch.closed) { ch.closed = true; ch.emit('close'); }
  };
  ch.signal = (_signal, cb) => cb?.();
  ch.complete = (value = 'healthy') => {
    ch.emit('data', Buffer.from(value)); ch.emit('exit', 0); ch.emit('close', 0);
  };
  return ch;
}

function fixture({ sftp, exec, poolSize = 1, channelsPerConnection = 1 } = {}) {
  const clients = [], requests = [];
  const requestReady = deferred();
  const bridge = createBridge({ default: 'fake', knownHosts: [], poolSize, channelsPerConnection,
    hosts: { fake: { host: 'unit.test.invalid', port: 22, user: 'unit' } } }, {
    // Explicit inert path prevents even consulting SSH_BRIDGE_CONFIG.
    configFile: __filename,
    clientFactory() {
      const c = new EventEmitter();
      c.index = clients.length; c.sftpCalls = 0; c.endCalls = 0; c.execCalls = 0;
      clients.push(c);
      c.connect = () => queueMicrotask(() => c.emit('ready'));
      c.end = () => { c.endCalls++; if (!c.ended) { c.ended = true; c.emit('close'); } };
      c.sftp = cb => {
        c.sftpCalls++;
        const request = { client: c, callback: cb };
        requests.push(request); requestReady.resolve(request);
        if (sftp) sftp(c, cb, requests.length);
      };
      c.exec = (command, options, cb) => {
        c.execCalls++;
        if (!exec) throw new Error('unexpected exec');
        exec(c, command, options, cb);
      };
      return c;
    },
  });
  return { bridge, clients, requests, requestReady: requestReady.promise,
    close: () => bridge.close(), sftpCalls: () => clients.reduce((sum, c) => sum + c.sftpCalls, 0) };
}

async function main() {
  await test('concurrent initial listDir callers share exactly one SFTP opening', async () => {
    const f = fixture(), s = session();
    try {
      const polls = ['/a', '/b', '/c'].map(p => f.bridge.listDir('fake', p, { timeoutMs: 1000 }));
      const first = await bounded(f.requestReady);
      await tick();
      assert.equal(f.clients.length, 1); assert.equal(f.sftpCalls(), 1);
      first.callback(null, s);
      const values = await bounded(Promise.all(polls));
      assert.deepEqual(values.map(r => r.path), ['/a', '/b', '/c']);
      assert(values.every(r => r.count === 2 && r.entries[0].name === 'subdir'));
      await f.bridge.listDir('fake', '/cached', { timeoutMs: 1000 });
      assert.equal(s.calls.readdir, 4); assert.equal(f.sftpCalls(), 1);
    } finally { f.close(); }
  });

  await test('hung sftp-open observes deadline and disposes late session, then recovers', async () => {
    const recovered = session();
    const f = fixture({ sftp(_c, cb, n) { if (n > 1) cb(null, recovered); } });
    try {
      const pending = outcome(f.bridge.listDir('fake', '/', { timeoutMs: 60 }));
      const request = await bounded(f.requestReady);
      const result = await bounded(pending);
      assert.equal(result.error?.code, 'TIMEOUT'); assert.equal(request.client.ended, true);
      const late = session(); request.callback(null, late);
      assert.equal(late.calls.end, 1); assert.equal(late.calls.readdir, 0);
      const next = await bounded(f.bridge.listDir('fake', '/next', { timeoutMs: 1000 }));
      assert.equal(next.count, 2); assert.equal(f.clients.length, 2); assert.equal(f.sftpCalls(), 2);
    } finally { f.close(); }
  });

  await test('explicit cancellation during opening disposes late session and next call succeeds', async () => {
    const recovered = session();
    const f = fixture({ sftp(_c, cb, n) { if (n > 1) cb(null, recovered); } });
    const controller = new AbortController();
    try {
      const pending = outcome(f.bridge.listDir('fake', '/', { timeoutMs: 1000, signal: controller.signal }));
      const request = await bounded(f.requestReady);
      controller.abort();
      assert.equal((await bounded(pending)).error?.code, 'CANCELLED');
      const next = await bounded(f.bridge.listDir('fake', '/next', { timeoutMs: 1000 }));
      assert.equal(next.count, 2);
      const late = session(); request.callback(null, late);
      assert.equal(late.calls.end, 1); assert.equal(recovered.calls.end, 0);
    } finally { controller.abort(); f.close(); }
  });

  await test('transport close while sftp-open is pending rejects promptly, not at deadline', async () => {
    const controller = new AbortController();
    const f = fixture({ sftp(_c, cb, n) { if (n > 1) cb(null, session()); } });
    let pending;
    try {
      pending = outcome(f.bridge.listDir('fake', '/', { timeoutMs: 1000, signal: controller.signal }));
      const request = await bounded(f.requestReady);
      request.client.emit('close');
      const result = await Promise.race([pending, tick().then(() => ({ stillPending: true }))]);
      assert.notEqual(result.stillPending, true, 'transport loss left sftp-open pending until the operation deadline');
      assert(result.error, 'transport close must reject, not return an empty successful listing');
      assert.notEqual(result.error.code, 'TIMEOUT');
      const late = session(); request.callback(null, late);
      assert.equal(late.calls.end, 1);
      assert.equal((await bounded(f.bridge.listDir('fake', '/after-close', { timeoutMs: 1000 }))).count, 2);
    } finally { controller.abort(); await pending; f.close(); }
  });

  await test('sftp-open error is propagated without replay and releases capacity for next call', async () => {
    const failure = Object.assign(new Error('SFTP subsystem unavailable'), { code: 'SFTP_OPEN_REFUSED' });
    const f = fixture({ sftp(_c, cb, n) { queueMicrotask(() => n === 1 ? cb(failure) : cb(null, session())); } });
    try {
      await assert.rejects(f.bridge.listDir('fake', '/', { timeoutMs: 1000 }), error => error === failure);
      assert.equal(f.sftpCalls(), 1);
      assert.equal((await f.bridge.listDir('fake', '/retry', { timeoutMs: 1000 })).count, 2);
      assert.equal(f.sftpCalls(), 2); assert.equal(f.clients.length, 1);
    } finally { f.close(); }
  });

  await test('late stat callback after cancellation cannot dispatch a file open', async () => {
    const called = deferred(); let complete;
    const old = session({ stat(_p, cb) { complete = cb; called.resolve(); } });
    const replacement = session();
    const f = fixture({ sftp(_c, cb, n) { cb(null, n === 1 ? old : replacement); } });
    const controller = new AbortController();
    try {
      const pending = outcome(f.bridge.readFile('fake', '/data', { timeoutMs: 1000, signal: controller.signal }));
      await bounded(called.promise); controller.abort();
      assert.equal((await bounded(pending)).error?.code, 'CANCELLED');
      assert.equal((await f.bridge.listDir('fake', '/recovered', { timeoutMs: 1000 })).count, 2);
      complete(null, { mode: 0o100644, size: 10 });
      await tick();
      assert.equal(old.calls.open, 0, 'cancelled helper continued to dispatch SFTP requests');
      assert.equal(replacement.calls.end, 0);
    } finally { controller.abort(); f.close(); }
  });

  for (const event of ['close', 'error']) {
    await test(`late ${event} from disposed SFTP cannot invalidate its replacement`, async () => {
      const entered = deferred(); let complete;
      const old = session({ autoClose: false, readdir(_p, cb) { complete = cb; entered.resolve(); } });
      const replacement = session();
      const f = fixture({ sftp(_c, cb, n) { cb(null, n === 1 ? old : replacement); } });
      const controller = new AbortController();
      try {
        const pending = outcome(f.bridge.listDir('fake', '/', { timeoutMs: 1000, signal: controller.signal }));
        await bounded(entered.promise); controller.abort();
        assert.equal((await bounded(pending)).error?.code, 'CANCELLED');
        assert.equal((await f.bridge.listDir('fake', '/new', { timeoutMs: 1000 })).count, 2);
        const healthy = f.clients[1];
        assert.equal(healthy.ended, undefined); assert.equal(replacement.calls.end, 0);
        if (event === 'error') old.emit('error', new Error('late old session error'));
        else old.emit('close');
        await tick();
        assert.equal(replacement.calls.end, 0, `old SFTP ${event} disposed the replacement session`);
        assert.equal(healthy.ended, undefined, `old SFTP ${event} closed a healthy replacement transport`);
        complete(null, directory);
        assert.equal((await f.bridge.listDir('fake', '/still-cached', { timeoutMs: 1000 })).count, 2);
        assert.equal(f.sftpCalls(), 2);
      } finally { controller.abort(); f.close(); }
    });
  }

  await test('short SFTP packets and zero-size pseudo files decode complete UTF-8 through createBridge', async () => {
    for (const reported of [0, 60000]) {
      const bytes = Buffer.from('用户🙂\n'.repeat(5000));
      const s = session({ data: bytes, maxChunk: 17, reportedSize: reported === 0 ? 0 : bytes.length });
      const f = fixture({ sftp(_c, cb) { cb(null, s); } });
      try {
        const r = await bounded(f.bridge.readFile('fake', '/short-packets', { timeoutMs: 1000 }));
        assert.equal(r.content, bytes.toString()); assert.equal(r.bytes, bytes.length);
        assert.equal(r.truncated, false); assert.equal(s.calls.open, 1); assert.equal(s.calls.close, 1);
        assert(s.calls.read > 100, 'fixture must exercise many short packets');
      } finally { f.close(); }
    }
  });

  await test('cancellation during file read cannot resume read loop after a late callback', async () => {
    const reading = deferred(); let complete;
    const old = session({ data: Buffer.from('abcdef'), read(_h, buffer, offset, _length, _position, cb) {
      complete = () => { buffer[offset] = 97; cb(null, 1); }; reading.resolve();
    } });
    const replacement = session();
    const f = fixture({ sftp(_c, cb, n) { cb(null, n === 1 ? old : replacement); } });
    const controller = new AbortController();
    try {
      const pending = outcome(f.bridge.readFile('fake', '/delayed-read', { timeoutMs: 1000, signal: controller.signal }));
      await bounded(reading.promise); controller.abort();
      assert.equal((await bounded(pending)).error?.code, 'CANCELLED');
      assert.equal((await f.bridge.listDir('fake', '/new', { timeoutMs: 1000 })).count, 2);
      complete(); await tick();
      assert.equal(old.calls.read, 1, 'late read result restarted the cancelled read loop');
      assert.equal(replacement.calls.end, 0);
    } finally { controller.abort(); f.close(); }
  });

  await test('cancelled SFTP transport does not interrupt a healthy sibling exec transport', async () => {
    const accepted = deferred(), entered = deferred(), ch = channel();
    const failed = session({ readdir(_p, _cb) { entered.resolve(); } });
    const recovered = session();
    const f = fixture({ poolSize: 2, channelsPerConnection: 1,
      exec(_c, _command, _options, cb) { cb(null, ch); accepted.resolve(); },
      sftp(_c, cb, n) { cb(null, n === 1 ? failed : recovered); } });
    const controller = new AbortController();
    let running;
    try {
      running = f.bridge.runCommand('fake', { command: 'held fake command', timeoutMs: 1000 });
      await bounded(accepted.promise);
      const listing = outcome(f.bridge.listDir('fake', '/', { timeoutMs: 1000, signal: controller.signal }));
      await bounded(entered.promise);
      assert.equal(f.clients.length, 2); assert.equal(f.requests[0].client.index, 1);
      controller.abort(); assert.equal((await bounded(listing)).error?.code, 'CANCELLED');
      assert.equal(f.clients[0].endCalls, 0, 'failure must not invalidate all connections on the host');
      assert.equal(ch.closeCalls, 0);
      ch.complete('sibling survived');
      const result = await bounded(running);
      assert.equal(result.exitCode, 0); assert.equal(result.stdout, 'sibling survived');
      assert.equal(result.outcome, undefined);
      assert.equal((await f.bridge.listDir('fake', '/recovered', { timeoutMs: 1000 })).count, 2);
    } finally { controller.abort(); ch.complete(); await running?.catch(() => {}); f.close(); }
  });

  console.log(`SFTP lifecycle checks: ${passed} passed, ${failures.length} failed`);
  if (failures.length) {
    for (const { name } of failures) console.error(`  - ${name}`);
    process.exitCode = 1;
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
