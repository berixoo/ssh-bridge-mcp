#!/usr/bin/env node
// Offline tunnel checks: only local TCP sockets and fake SSH forwardOut channels.
// Run directly with node scripts/tunnels-check.js (no config or SSH server).
const assert = require('node:assert/strict');
const net = require('node:net');
const { once } = require('node:events');
const { AsyncLocalStorage } = require('node:async_hooks');
const { PassThrough } = require('node:stream');
const { randomBytes } = require('node:crypto');
const { test } = require('node:test');
const { createTunnels } = require('../src/tunnels');

const failure = (code, message) => Object.assign(new Error(message), { code });
const turn = () => new Promise((resolve) => setImmediate(resolve));
async function listen(server, host = '127.0.0.1', port = 0) {
  server.listen({ host, port });
  await once(server, 'listening');
  return server.address().port;
}
async function stop(server) { await new Promise((resolve) => server.close(resolve)); }
async function connect(port, host = '127.0.0.1') {
  const socket = net.connect({ host, port });
  socket.on('error', () => {});
  await once(socket, 'connect');
  return socket;
}
function closed(socket) {
  return socket.closed ? Promise.resolve() : new Promise((resolve) => socket.once('close', resolve));
}
async function exchange(port, payload, host) {
  const socket = await connect(port, host);
  const chunks = [];
  socket.on('data', (chunk) => chunks.push(chunk));
  const ended = once(socket, 'end');
  socket.end(payload);
  await ended;
  await closed(socket);
  return Buffer.concat(chunks);
}
async function refused(port, host = '127.0.0.1') {
  const socket = net.connect({ port, host });
  await new Promise((resolve, reject) => {
    socket.once('error', (err) => err.code === 'ECONNREFUSED' ? resolve() : reject(err));
    socket.once('connect', () => { socket.destroy(); reject(new Error('listener leaked')); });
  });
}
async function fixture(t) {
  const sockets = new Set();
  const target = net.createServer({ allowHalfOpen: true }, (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    socket.pipe(socket);
  });
  const targetPort = await listen(target);
  const calls = [];
  const channels = new Set();
  const entries = new Map();
  let forward;
  const contexts = new AsyncLocalStorage();
  const runtime = {
    calls: 0,
    failure,
    context: () => contexts.getStore(),
    check() { if (this.context()?.signal.aborted) throw this.context().signal.reason; },
    async connection(name) { this.calls++; return entries.get(name); },
    wait(promise, onAbort) {
      const signal = this.context()?.signal;
      if (!signal) return promise;
      return new Promise((resolve, reject) => {
        const abort = () => { onAbort?.(); finish(signal.reason); };
        let done = false;
        const finish = (err, value) => {
          if (done) return;
          done = true;
          signal.removeEventListener('abort', abort);
          if (err) reject(err); else resolve(value);
        };
        Promise.resolve(promise).then((value) => finish(null, value), (err) => finish(err));
        if (signal.aborted) abort(); else signal.addEventListener('abort', abort, { once: true });
      });
    },
    acquire() { throw new Error('tunnels must not consume session slots'); },
  };
  for (const name of ['alpha', 'beta']) {
    entries.set(name, { closing: false, owners: new Set(), client: {
      forwardOut(srcIP, srcPort, dstIP, dstPort, cb) {
        calls.push({ name, srcIP, srcPort, dstIP, dstPort });
        if (forward) return forward(cb);
        const channel = net.connect({ host: '127.0.0.1', port: targetPort, allowHalfOpen: true });
        channels.add(channel);
        channel.on('error', () => {});
        channel.once('close', () => channels.delete(channel));
        channel.once('connect', () => cb(null, channel));
      },
      exec() { throw new Error('tunnels must only use direct-tcpip'); },
    } });
  }
  const tunnels = createTunnels({ runtime, resolveName(name) {
    const resolved = name === undefined || name === 'alias' ? 'alpha' : name;
    if (!entries.has(resolved)) throw failure('UNKNOWN_HOST', 'unknown host');
    return resolved;
  } });
  t.after(async () => {
    await tunnels.shutdown();
    for (const channel of channels) channel.destroy();
    for (const socket of sockets) socket.destroy();
    await stop(target);
  });
  return { tunnels, runtime, calls, entries, channels, targetPort,
    setForward(fn) { forward = fn; },
    withSignal(signal, fn) { return contexts.run({ signal }, fn); },
    fail(name) {
      const entry = entries.get(name);
      entry.closing = true;
      for (const cleanup of [...entry.owners]) cleanup();
      entry.owners.clear();
    },
  };
}

test('loopback defaults, direct-tcpip metadata, binary backpressure and half-close', { timeout: 10000 }, async (t) => {
  const f = await fixture(t);
  const descriptor = await f.tunnels.open(undefined, { remote_port: f.targetPort });
  assert.deepEqual(Object.keys(descriptor).sort(), ['host', 'local_host', 'local_port', 'remote_host', 'remote_port', 'tunnel_id']);
  assert.equal(descriptor.host, 'alpha');
  assert.equal(descriptor.local_host, '127.0.0.1');
  assert.equal(descriptor.remote_host, '127.0.0.1');
  assert.ok(descriptor.local_port > 0);
  const payload = randomBytes(4 * 1024 * 1024 + 17);
  assert.deepEqual(await exchange(descriptor.local_port, payload), payload);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].dstPort, f.targetPort);
  assert.equal(f.calls[0].dstIP, '127.0.0.1');
  assert.equal(f.calls[0].srcIP, '127.0.0.1');
  assert.ok(f.calls[0].srcPort > 0);
  assert.equal(f.runtime.calls, 1);
});

test('remote EOF drains buffered bytes to a slow local reader', { timeout: 10000 }, async (t) => {
  const f = await fixture(t);
  const payload = randomBytes(8 * 1024 * 1024 + 19);
  f.setForward((cb) => {
    const channel = new PassThrough();
    cb(null, channel);
    channel.end(payload);
  });
  const a = await f.tunnels.open('alpha', { remote_port: 80 });
  const socket = await connect(a.local_port);
  socket.pause();
  await new Promise((resolve) => setTimeout(resolve, 100));
  const chunks = [];
  socket.on('data', (chunk) => chunks.push(chunk));
  const ended = once(socket, 'end');
  socket.resume();
  await ended;
  socket.end();
  await closed(socket);
  assert.deepEqual(Buffer.concat(chunks), payload);
});

test('list is isolated by resolved host and descriptors cannot mutate state', async (t) => {
  const f = await fixture(t);
  const a = await f.tunnels.open('alias', { remote_port: 80 });
  const b = await f.tunnels.open('beta', { remote_host: 'service.internal', remote_port: 443 });
  assert.deepEqual(f.tunnels.list(), [a, b]);
  assert.deepEqual(f.tunnels.list('alias'), [a]);
  assert.deepEqual(f.tunnels.list('beta'), [b]);
  f.tunnels.list()[0].remote_port = 999;
  assert.equal(f.tunnels.list()[0].remote_port, 80);
  await f.tunnels.close(a.tunnel_id);
  assert.deepEqual(f.tunnels.list(), [b]);
  assert.deepEqual(await f.tunnels.close(a.tunnel_id), { tunnel_id: a.tunnel_id, closed: true });
  await refused(a.local_port);
});

test('explicit non-loopback bind is allowed, without changing loopback default', async (t) => {
  const f = await fixture(t);
  const a = await f.tunnels.open('alpha', { remote_port: 80, local_host: '0.0.0.0' });
  assert.equal(a.local_host, '0.0.0.0');
  assert.equal((await exchange(a.local_port, Buffer.from('LAN opt-in'))).toString(), 'LAN opt-in');
});

test('bridge-level validation rejects invalid hosts, ports, options and IDs before connecting', async (t) => {
  const f = await fixture(t);
  for (const options of [null, [], 'bad', {}, { remote_port: 0 }, { remote_port: 65536 },
    { remote_port: 1.5 }, { remote_port: '80' }, { remote_port: 80, local_port: -1 },
    { remote_port: 80, local_port: 65536 }, { remote_port: 80, local_port: '0' },
    { remote_port: 80, remote_host: '' }, { remote_port: 80, local_host: null },
    { remote_port: 80, local_host: 'host\nname' }, { remote_port: 80, remote_host: 'a/b' },
    { remote_port: 80, local_host: ':' }, { remote_port: 80, remote_host: '%' },
    { remote_port: 80, remote_host: 'two..dots' }]) {
    await assert.rejects(f.tunnels.open('alpha', options), { code: 'INVALID_ARGUMENT' });
  }
  for (const name of ['', ' ', null, 12]) {
    await assert.rejects(f.tunnels.open(name, { remote_port: 80 }), { code: 'INVALID_ARGUMENT' });
  }
  await assert.rejects(f.tunnels.open('missing', { remote_port: 80 }), { code: 'UNKNOWN_HOST' });
  await assert.rejects(f.tunnels.close(''), { code: 'INVALID_ARGUMENT' });
  assert.throws(() => f.tunnels.list(1), { code: 'INVALID_ARGUMENT' });
  assert.equal(f.runtime.calls, 0);
});

test('port conflicts do not close the existing listener or retain owners', async (t) => {
  const f = await fixture(t);
  const first = await f.tunnels.open('alpha', { remote_port: 80 });
  await assert.rejects(f.tunnels.open('alpha', { remote_port: 80, local_port: first.local_port }), { code: 'EADDRINUSE' });
  assert.deepEqual(f.tunnels.list(), [first]);
  assert.equal(f.entries.get('alpha').owners.size, 1);
  assert.equal((await exchange(first.local_port, Buffer.from('still open'))).toString(), 'still open');
});

test('forwardOut rejection and synchronous throw close only the accepted socket', async (t) => {
  const f = await fixture(t);
  const a = await f.tunnels.open('alpha', { remote_port: 80 });
  for (const implementation of [(cb) => cb(new Error('refused')), () => { throw new Error('disconnected'); }]) {
    f.setForward(implementation);
    const socket = await connect(a.local_port);
    await closed(socket);
    assert.equal(f.tunnels.list().length, 1);
  }
  f.setForward(null);
  assert.equal((await exchange(a.local_port, Buffer.from('retry is a new socket'))).toString(), 'retry is a new socket');
  assert.equal(f.runtime.calls, 1);
});

test('channel errors destroy the paired socket and detach error listeners', async (t) => {
  const f = await fixture(t);
  let channel;
  f.setForward((cb) => { channel = new PassThrough(); cb(null, channel); });
  const a = await f.tunnels.open('alpha', { remote_port: 80 });
  const socket = await connect(a.local_port);
  while (!channel) await turn();
  channel.emit('error', new Error('channel failed'));
  await closed(socket);
  await turn();
  assert.equal(channel.destroyed, true);
  assert.equal(channel.listenerCount('error'), 0);
  assert.equal(f.tunnels.list().length, 1);
});

test('close destroys active and opening channels and discards late callbacks', async (t) => {
  const f = await fixture(t);
  const a = await f.tunnels.open('alpha', { remote_port: 80 });
  const live = await connect(a.local_port);
  await turn();
  let callback;
  f.setForward((cb) => { callback = cb; });
  const pending = await connect(a.local_port);
  while (!callback) await turn();
  await f.tunnels.close(a.tunnel_id);
  await Promise.all([closed(live), closed(pending)]);
  const late = new PassThrough();
  callback(null, late);
  assert.equal(late.destroyed, true);
  await turn();
  assert.equal(late.listenerCount('error'), 0);
  assert.equal(f.entries.get('alpha').owners.size, 0);
  await refused(a.local_port);
});

test('failed owning transport removes its listeners and streams without reconnecting', async (t) => {
  const f = await fixture(t);
  const a = await f.tunnels.open('alpha', { remote_port: 80 });
  const b = await f.tunnels.open('alpha', { remote_port: 81 });
  const other = await f.tunnels.open('beta', { remote_port: 82 });
  const socket = await connect(a.local_port);
  await turn();
  const before = f.runtime.calls;
  f.fail('alpha');
  await closed(socket);
  await turn();
  assert.deepEqual(f.tunnels.list(), [other]);
  await Promise.all([refused(a.local_port), refused(b.local_port)]);
  assert.equal(f.runtime.calls, before);
  assert.equal((await exchange(other.local_port, Buffer.from('other transport'))).toString(), 'other transport');
});

test('operation cancellation during listen leaves no listener or owner', async (t) => {
  const f = await fixture(t);
  const reservation = net.createServer();
  const port = await listen(reservation);
  await stop(reservation);
  const controller = new AbortController();
  const originalWait = f.runtime.wait;
  let waits = 0;
  f.runtime.wait = function(promise, cleanup) {
    if (++waits === 2) controller.abort(failure('CANCELLED', 'cancelled'));
    return originalWait.call(this, promise, cleanup);
  };
  await assert.rejects(f.withSignal(controller.signal, () => f.tunnels.open('alpha', { remote_port: 80, local_port: port, local_host: 'localhost' })), { code: 'CANCELLED' });
  await turn();
  assert.deepEqual(f.tunnels.list(), []);
  assert.equal(f.entries.get('alpha').owners.size, 0);
  const replacement = net.createServer();
  await listen(replacement, 'localhost', port);
  await stop(replacement);
});

test('already-cancelled operation and cancellation after bind are checked', async (t) => {
  const f = await fixture(t);
  const controller = new AbortController();
  controller.abort(failure('CANCELLED', 'cancelled'));
  await assert.rejects(f.withSignal(controller.signal, () => f.tunnels.open('alpha', { remote_port: 80 })), { code: 'CANCELLED' });
  assert.equal(f.runtime.calls, 0);
  const later = new AbortController();
  const originalWait = f.runtime.wait;
  f.runtime.wait = async function(promise, cleanup) {
    const value = await originalWait.call(this, promise, cleanup);
    if (cleanup) later.abort(failure('CANCELLED', 'cancelled after binding'));
    return value;
  };
  await assert.rejects(f.withSignal(later.signal, () => f.tunnels.open('alpha', { remote_port: 80 })), { code: 'CANCELLED' });
  assert.deepEqual(f.tunnels.list(), []);
  assert.equal(f.entries.get('alpha').owners.size, 0);
});

test('cancellation while waiting for transport cannot create a late listener', async (t) => {
  const f = await fixture(t);
  let resolveConnection;
  f.runtime.connection = () => new Promise((resolve) => { resolveConnection = resolve; });
  const controller = new AbortController();
  const opening = f.withSignal(controller.signal, () => f.tunnels.open('alpha', { remote_port: 80 }));
  controller.abort(failure('TIMEOUT', 'operation deadline'));
  await assert.rejects(opening, { code: 'TIMEOUT' });
  resolveConnection(f.entries.get('alpha'));
  await turn();
  assert.deepEqual(f.tunnels.list(), []);
  assert.equal(f.entries.get('alpha').owners.size, 0);
});

test('a transport that closed before ownership registration is rejected', async (t) => {
  const f = await fixture(t);
  f.entries.get('alpha').closing = true;
  await assert.rejects(f.tunnels.open('alpha', { remote_port: 80 }), { code: 'CONNECTION_CLOSED' });
  assert.deepEqual(f.tunnels.list(), []);
  assert.equal(f.entries.get('alpha').owners.size, 0);
});

test('transport failure or shutdown while opening settles the open promise', async (t) => {
  for (const action of ['fail', 'shutdown']) {
    const f = await fixture(t);
    const originalWait = f.runtime.wait;
    f.runtime.wait = function(promise, cleanup) {
      if (cleanup) {
        if (action === 'fail') f.fail('alpha');
        else void f.tunnels.shutdown();
      }
      return originalWait.call(this, promise, cleanup);
    };
    await assert.rejects(f.tunnels.open('alpha', { remote_port: 80 }), { code: 'TUNNEL_CLOSED' });
    assert.equal(f.entries.get('alpha').owners.size, 0);
  }
});

test('each forwardOut is bounded to 15 seconds and late channels are destroyed', { timeout: 10000 }, async (t) => {
  const f = await fixture(t);
  const a = await f.tunnels.open('alpha', { remote_port: 80 });
  let callback;
  f.setForward((cb) => { callback = cb; });
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const socket = await connect(a.local_port);
  while (!callback) await turn();
  t.mock.timers.tick(14999);
  assert.equal(socket.destroyed, false);
  t.mock.timers.tick(1);
  await closed(socket);
  const late = new PassThrough();
  callback(null, late);
  assert.equal(late.destroyed, true);
  assert.equal(f.tunnels.list().length, 1);
  assert.equal(f.runtime.calls, 1);
  t.mock.timers.reset();
});

test('shutdown closes everything, is idempotent, and prevents new listeners', async (t) => {
  const f = await fixture(t);
  const a = await f.tunnels.open('alpha', { remote_port: 80 });
  const b = await f.tunnels.open('beta', { remote_port: 80 });
  const socket = await connect(a.local_port);
  await f.tunnels.shutdown();
  await f.tunnels.shutdown();
  await closed(socket);
  await Promise.all([refused(a.local_port), refused(b.local_port)]);
  assert.equal(f.entries.get('alpha').owners.size, 0);
  assert.equal(f.entries.get('beta').owners.size, 0);
  await assert.rejects(f.tunnels.open('alpha', { remote_port: 80 }), { code: 'CLOSED' });
  await f.tunnels.close(a.tunnel_id);
});
