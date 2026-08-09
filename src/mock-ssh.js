const { EventEmitter } = require('events');

function makeChannel(res = {}) {
  const { code = 0, stdout = '', stderr = '', onWrite, _neverClose } = res;
  const ch = new EventEmitter();
  ch.stderr = new EventEmitter();
  ch.setWindow = () => {};
  ch.signal = (_sig, cb) => cb && cb(null);
  ch.stdin = {
    writes: [],
    end: () => {},
    write: (data) => {
      ch.stdin.writes.push(data.toString());
      if (onWrite) onWrite(data.toString());
      return true;
    },
  };
  setImmediate(() => {
    ch.emit('ready');
    if (stdout) ch.emit('data', Buffer.from(stdout));
    if (stderr) ch.stderr.emit('data', Buffer.from(stderr));
    if (!_neverClose) ch.emit('close', code);
  });
  return ch;
}

function makeSftp() {
  const files = new Map();
  return {
    _files: files,
    mkdir: (p, opts, cb) => { if (typeof opts === 'function') { cb = opts; opts = {}; } cb(null); },
    writeFile: (p, data, cb) => { files.set(p, Buffer.from(data)); cb(null); },
    readFile: (p, enc, cb) => {
      if (typeof enc === 'function') { cb = enc; enc = 'utf8'; }
      const b = files.get(p);
      if (!b) return cb(new Error(`ENOENT: ${p}`));
      cb(null, enc === 'utf8' ? b.toString('utf8') : b);
    },
    fastPut: (lp, rp, cb) => { files.set(rp, Buffer.from(String(lp))); cb(null); },
    fastGet: (rp, lp, cb) => {
      if (!files.has(rp)) return cb(new Error(`ENOENT: ${rp}`));
      files.set(String(lp), files.get(rp));
      cb(null);
    },
    open: (p, _mode, cb) => cb(null, { _p: p }),
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
  return function factory() {
    const client = new EventEmitter();
    client.calls = [];
    client.exec = (command, opts, cb) => {
      if (typeof opts === 'function') { cb = opts; opts = {}; }
      client.calls.push({ type: 'exec', command, opts });
      const res = onExec ? onExec(command, opts) : {};
      const ch = makeChannel(res);
      client._lastChannel = ch;
      cb(null, ch);
    };
    client.sftp = (cb) => {
      client.calls.push({ type: 'sftp' });
      cb(null, onSftp ? onSftp() : makeSftp());
    };
    client.end = () => client.emit('close');
    setImmediate(() => client.emit('ready'));
    return client;
  };
}

module.exports = { createMockClientFactory, makeSftp };
