// Connection ownership and end-to-end operation deadlines. No operation replay.
const net = require('net');
const fs = require('fs');
const path = require('path');
const { AsyncLocalStorage } = require('async_hooks');

function failure(code, message) { return Object.assign(new Error(message), { code }); }

function createRuntime({ cfg, configFile, clientFactory, realClient, resolveHost, algorithms, verify }) {
  const contexts = new AsyncLocalStorage();
  const hosts = new Map();
  let closed = false;
  const poolSize = cfg.poolSize || 4;
  const channels = cfg.channelsPerConnection || 6;
  const state = (name) => {
    if (!hosts.has(name)) hosts.set(name, { entries: [], pending: null, waiters: new Set(), generation: 0 });
    return hosts.get(name);
  };
  function context() { return contexts.getStore(); }
  function operation(options, fn) {
    if (context()) return fn();
    const controller = new AbortController();
    const signal = options?.signal;
    const ms = options?.timeoutMs ?? 60000;
    const cancel = () => controller.abort(failure('CANCELLED', 'operation cancelled'));
    const timer = setTimeout(() => controller.abort(failure('TIMEOUT', `operation timed out after ${ms}ms`)), ms);
    if (signal?.aborted) cancel();
    else signal?.addEventListener('abort', cancel, { once: true });
    const ctx = { signal: controller.signal, deadline: Date.now() + ms };
    return contexts.run(ctx, async () => {
      try { check(); return await fn(); }
      finally { clearTimeout(timer); signal?.removeEventListener('abort', cancel); }
    });
  }
  function check() {
    if (closed) throw failure('CLOSED', 'SSH bridge is closed');
    if (context()?.signal.aborted) throw context().signal.reason;
  }
  function wait(promise, onAbort) {
    const signal = context()?.signal;
    if (!signal) return promise;
    return new Promise((resolve, reject) => {
      let done = false;
      const finish = (err, value) => {
        if (done) return;
        done = true;
        signal.removeEventListener('abort', abort);
        if (err) reject(err); else resolve(value);
      };
      const abort = () => { try { onAbort?.(); } finally { finish(signal.reason); } };
      // Always attach a rejection handler even when already cancelled.
      Promise.resolve(promise).then((v) => finish(null, v), (e) => finish(e));
      if (signal.aborted) abort(); else signal.addEventListener('abort', abort, { once: true });
    });
  }
  function notify(s) { for (const wake of [...s.waiters]) wake(); }
  function invalidate(entry) {
    if (!entry || entry.closing) return;
    entry.closing = true;
    const s = state(entry.name);
    s.entries = s.entries.filter((e) => e !== entry);
    s.generation++;
    for (const cleanup of [...entry.owners]) { try { cleanup(); } catch (_) {} }
    entry.owners.clear();
    try { entry.client.end(); } catch (_) {}
    entry.socket?.destroy();
    notify(s);
  }
  async function open(name) {
    const s = state(name);
    if (s.pending) return s.pending;
    s.pending = (async () => {
      const host = resolveHost(name);
      let socket;
      check();
      if (realClient) {
        socket = await new Promise((resolve, reject) => {
          const sock = new net.Socket();
          sock.setNoDelay(true);
          sock.setKeepAlive(true, 30000);
          const timer = setTimeout(() => { sock.destroy(); reject(failure('CONNECT_TIMEOUT', `TCP connection to ${name} timed out`)); }, 15000);
          sock.once('error', (e) => { clearTimeout(timer); reject(e); });
          s.cancelOpen = () => { clearTimeout(timer); sock.destroy(); reject(failure('CLOSED', 'bridge closed during TCP connection')); };
          sock.once('connect', () => { clearTimeout(timer); resolve(sock); });
          try { sock.connect({ host: host.host, port: host.port }); }
          catch (e) { clearTimeout(timer); sock.destroy(); reject(e); }
        });
      }
      let client;
      try { client = clientFactory({ sock: socket }); }
      catch (e) { socket?.destroy(); throw e; }
      const entry = { name, client, socket, channels: 0, closing: false, owners: new Set(), generation: s.generation };
      let handshakeTimer;
      try {
        await new Promise((resolve, reject) => {
          let ready = false;
          let reason;
          const timer = handshakeTimer = setTimeout(() => reject(failure('CONNECT_TIMEOUT', `SSH handshake to ${name} timed out`)), 15000);
          s.cancelOpen = () => { clearTimeout(timer); reject(failure('CLOSED', 'bridge closed during SSH handshake')); invalidate(entry); };
          client.on('ready', () => { ready = true; clearTimeout(timer); resolve(); });
          client.on('error', (e) => { clearTimeout(timer); reject(failure('CONNECTION_FAILED', `SSH connection to ${name} failed: ${reason || e.message}`)); invalidate(entry); });
          client.on('close', () => { clearTimeout(timer); if (!ready) reject(failure('CONNECTION_FAILED', `SSH connection to ${name} closed before ready`)); invalidate(entry); });
          let privateKey;
          if (host.privateKeyPath) privateKey = fs.readFileSync(path.resolve(path.dirname(configFile), host.privateKeyPath));
          client.connect({
            host: host.host, port: host.port, username: host.user,
            password: host.password, privateKey, passphrase: host.passphrase,
            agent: host.agent, agentForward: false,
            authHandler: ['none', ...(privateKey ? ['publickey'] : []), ...(host.agent ? ['agent'] : []), ...(host.password !== undefined ? ['password'] : [])],
            readyTimeout: 15000, keepaliveInterval: 15000, keepaliveCountMax: 3,
            sock: socket, algorithms,
            hostVerifier: (blob) => { const result = verify(host, blob); if (!result.ok) reason = result.message; return result.ok; },
          });
        });
        if (closed || entry.closing) throw failure('CLOSED', 'connection closed during establishment');
        s.entries.push(entry);
        return entry;
      } catch (e) { invalidate(entry); throw e; }
      finally { clearTimeout(handshakeTimer); }
    })();
    try { return await s.pending; }
    finally { s.cancelOpen = null; s.pending = null; notify(s); }
  }
  async function acquire(name) {
    const s = state(name);
    for (;;) {
      check();
      const free = s.entries.filter((e) => !e.closing && e.channels < channels).sort((a, b) => a.channels - b.channels)[0];
      if (free) {
        free.channels++;
        let released = false;
        return { entry: free, release() { if (released) return; released = true; free.channels--; notify(s); } };
      }
      if (s.pending || s.entries.length < poolSize) { await wait(open(name)); continue; }
      await new Promise((resolve) => {
        const signal = context()?.signal;
        const wake = () => {
          s.waiters.delete(wake);
          signal?.removeEventListener('abort', wake);
          resolve();
        };
        s.waiters.add(wake);
        signal?.addEventListener('abort', wake, { once: true });
        if (signal?.aborted) wake();
      });
    }
  }
  async function connection(name) {
    check();
    const s = state(name);
    return s.entries.find((e) => !e.closing) || wait(open(name));
  }
  function shutdown() {
    closed = true;
    for (const s of hosts.values()) { s.cancelOpen?.(); for (const e of [...s.entries]) invalidate(e); notify(s); }
  }
  return { operation, context, check, wait, acquire, connection, invalidate, shutdown, failure };
}
module.exports = { createRuntime, failure };
