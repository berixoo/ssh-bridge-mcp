const { EventEmitter } = require('events');
const path = require('path');

function makeChannel(res = {}) {
  const { code = 0, stdout = '', stderr = '', onWrite, _neverClose, _drop } = res;
  const ch = new EventEmitter();
  ch.stderr = new EventEmitter();
  ch.setWindow = () => {};
  ch.signal = (_sig, cb) => cb && cb(null);
  ch.stdin = {
    writes: [],
    end: () => {},
    write: (data, cb) => {
      ch.stdin.writes.push(data.toString());
      if (onWrite) onWrite(data.toString());
      // Node writable streams invoke the write callback when the data is
      // flushed; ssh2's stdin honors it too. nextTick (not setImmediate) so a
      // chained `write -> cb -> write -> cb -> end` finishes before the
      // channel's setImmediate close event, mirroring the real flush order.
      if (cb) process.nextTick(cb);
      return true;
    },
  };
  // stdout/stderr may be a string or an array of chunks; each element is
  // emitted as its own data event so accumulation and capping are exercised.
  const outChunks = Array.isArray(stdout) ? stdout : stdout ? [stdout] : [];
  const errChunks = Array.isArray(stderr) ? stderr : stderr ? [stderr] : [];
  setImmediate(() => {
    ch.emit('ready');
    if (_drop) {
      // Mid-command connection loss: error, then close without a code.
      ch.emit('error', new Error('mock connection reset'));
      ch.emit('close');
      return;
    }
    for (const c of outChunks) ch.emit('data', Buffer.from(c));
    for (const c of errChunks) ch.stderr.emit('data', Buffer.from(c));
    if (!_neverClose) ch.emit('close', code);
  });
  return ch;
}

function makeSftp() {
  const files = new Map();
  files.set('/', null); // root always exists, like a real filesystem
  return {
    _files: files,
    // Single-level semantics: mirror ssh2's non-recursive mkdir(path, attrs, cb).
    mkdir: (p, opts, cb) => {
      if (typeof opts === 'function') { cb = opts; opts = {}; }
      const parent = path.posix.dirname(p);
      if (!files.has(parent)) {
        const e = new Error(`ENOENT: no such file or directory: ${parent}`);
        e.code = 2;
        return cb(e);
      }
      files.set(p, null); // null marks a directory
      cb(null);
    },
    stat: (p, cb) => {
      if (!files.has(p)) {
        const e = new Error(`ENOENT: no such file or directory: ${p}`);
        e.code = 2;
        return cb(e);
      }
      cb(null, { size: files.get(p) === null ? 0 : (files.get(p) || Buffer.alloc(0)).length });
    },
    writeFile: (p, data, cb) => { files.set(p, Buffer.from(data)); cb(null); },
    readFile: (p, enc, cb) => {
      if (typeof enc === 'function') { cb = enc; enc = 'utf8'; }
      const b = files.get(p);
      if (b === undefined || b === null) {
        const e = new Error(`ENOENT: ${p}`);
        e.code = 2;
        return cb(e);
      }
      cb(null, enc === 'utf8' ? b.toString('utf8') : b);
    },
    fastPut: (lp, rp, cb) => { files.set(rp, Buffer.from(String(lp))); cb(null); },
    fastGet: (rp, lp, cb) => {
      if (!files.has(rp)) return cb(new Error(`ENOENT: ${rp}`));
      files.set(String(lp), files.get(rp));
      cb(null);
    },
    open: (p, _mode, cb) => {
      const v = files.get(p);
      if (v === undefined || v === null) {
        const e = new Error(`ENOENT: ${p}`);
        e.code = 2;
        return cb(e);
      }
      cb(null, { _p: p });
    },
    fstat: (h, cb) => cb(null, { size: (files.get(h._p) || Buffer.alloc(0)).length }),
    read: (h, buf, start, len, pos, cb) => {
      const b = files.get(h._p) || Buffer.alloc(0);
      const chunk = b.subarray(pos, pos + len);
      chunk.copy(buf, start);
      cb(null, chunk.length, chunk);
    },
    end: () => {},
  };
}

function createMockClientFactory({ onExec, onSftp } = {}) {
  function factory() {
    const client = new EventEmitter();
    client.calls = [];
    client.exec = (command, opts, cb) => {
      if (typeof opts === 'function') { cb = opts; opts = {}; }
      client.calls.push({ type: 'exec', command, opts });
      const res = onExec ? onExec(command, opts) : {};
      const ch = makeChannel(res);
      client._lastChannel = ch;
      cb(null, ch);
      if (res._drop) setImmediate(() => client.emit('close'));
    };
    client.sftp = (cb) => {
      client.calls.push({ type: 'sftp' });
      const s = onSftp ? onSftp() : makeSftp();
      client._sftp = s;
      cb(null, s);
    };
    client.connect = () => {};
    client.end = () => client.emit('close');
    setImmediate(() => client.emit('ready'));
    factory._clients.push(client);
    return client;
  }
  factory._clients = [];
  return factory;
}

module.exports = { createMockClientFactory, makeSftp };
