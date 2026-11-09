const { Client } = require('ssh2');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const path = require('path');
const { resolveHost, knownHostsPaths, configPath } = require('./config');
const { createKnownHostsStore, verifyHostKey } = require('./hostkeys');
const { checkLocalPath } = require('./paths');
const { buildCaptureScript, buildOptimizeScript, parseCaptureResult, looksLikeImage } = require('./screenshot');

const MAX_OUTPUT = 500 * 1024;
const BG_GRACE_MS = 1500;
const ANSI_RE = /\x1b\[[0-9;?]*[A-Za-z]/g;

// Bound a single download. 2 GiB is far above anything this bridge is meant to
// shuttle between a workstation and a local VM, while still stopping a remote
// from filling the local disk. maxDownloadBytes: 0 disables the check.
const DEFAULT_MAX_DOWNLOAD = 2 * 1024 * 1024 * 1024;

// ssh2's own defaults are already modern: CBC, 3DES, arcfour, ssh-dss and the
// sha1 KEX suites live only in its "supported" lists and are never offered
// unless asked for. What remains in the default offer is SHA-1 -- the ssh-rsa
// signature scheme and the hmac-sha1 MACs. Subtract those rather than pinning a
// list, so ssh2's capability filtering still decides what this build can do and
// an unsupported algorithm can never be requested.
const SHA1_REMOVALS = {
  serverHostKey: { remove: ['ssh-rsa'] },
  hmac: { remove: ['hmac-sha1', 'hmac-sha1-etm@openssh.com'] },
};

function connectAlgorithms(cfg) {
  if (cfg.allowLegacyAlgorithms === true) return cfg.algorithms;
  const out = { ...SHA1_REMOVALS };
  for (const [group, value] of Object.entries(cfg.algorithms || {})) {
    const mine = out[group];
    // An exact array replaces the default outright; an operation object
    // (append/prepend/remove) is merged so the SHA-1 removal survives.
    out[group] =
      mine && value && !Array.isArray(value) && typeof value === 'object'
        ? { ...mine, ...value }
        : value;
  }
  return out;
}

function downloadLimit(cfg) {
  if (cfg.maxDownloadBytes === undefined) return DEFAULT_MAX_DOWNLOAD;
  return cfg.maxDownloadBytes;
}

function stripAnsi(s) {
  return s.replace(ANSI_RE, '');
}

// ssh2 reports SFTP status failures as an Error whose .code is the SFTP status
// number; SSH_FX_NO_SUCH_FILE is 2.
function isNoSuchFile(err) {
  return !!err && (err.code === 2 || /no such file/i.test(err.message || ''));
}

// SFTP status codes as ssh2 assigns them (lib/protocol/SFTP.js STATUS_CODE).
// ssh2 puts the *number* in err.code and a short, often useless message like
// "Failure" in err.message, so the code is the only reliable signal. These are
// protocol status codes, not POSIX errno -- EISDIR/ENOTDIR never appear here.
const SFTP_STATUS = {
  1: 'EOF',
  2: 'NO_SUCH_FILE',
  3: 'PERMISSION_DENIED',
  4: 'FAILURE',
  5: 'BAD_MESSAGE',
  6: 'NO_CONNECTION',
  7: 'CONNECTION_LOST',
  8: 'OP_UNSUPPORTED',
};

// Turns an ssh2 SFTP error into a message an agent can branch on. "Failure"
// (code 4) is what the server returns for EISDIR/ENOTEMPTY and similar cases
// that SFTP has no dedicated status for, so the caller's own context is added
// to disambiguate: whether the path is a directory or a file is known at the
// call site.
function describeSftpError(err) {
  if (!err) return 'unknown error';
  const code = typeof err.code === 'number' ? err.code : null;
  const name = code === null ? null : SFTP_STATUS[code];
  if (!name) return err.message || String(err);
  const msg = err.message && err.message !== name ? `${err.message}` : '';
  return msg ? `${name} (${msg})` : name;
}

// True when the SFTP *session* is unusable (as opposed to the operation
// failing). Only these should discard the cached session and retry.
function isSftpSessionFailure(err) {
  const msg = (err && err.message) || '';
  return /no response from server|connection lost|not connected|channel open|session closed|SFTP channel closed/i.test(msg);
}

function shq(s) {
  return "'" + s.replace(/'/g, `'\\''`) + "'";
}

function makeExecCommand({ command, cwd, sudo, env, pipefail }) {
  let full = command;
  // Without pipefail `cat /etc/shadow | head -1` exits 0 even though cat failed,
  // which reports a permission error as success. Opt-in because it also turns
  // intentional `cmd | head` SIGPIPE exits into failures.
  if (pipefail) full = `set -o pipefail; ${full}`;
  if (env && Object.keys(env).length > 0) {
    // ssh2's opts.env is delivered via SSH env channel requests, which
    // OpenSSH ignores for exec sessions by default (PermitUserEnvironment
    // off, no AcceptEnv). Emit exports directly into the command string so
    // env always reaches the remote shell regardless of sshd config.
    const exports = Object.entries(env)
      .map(([k, v]) => `export ${k}=${shq(String(v))};`)
      .join(' ');
    full = `${exports} ${full}`;
  }
  // sudo and cwd wrap the *current* full string so env exports stay visible
  // to the wrapped command (they run inside the sudo'd shell too).
  if (sudo) full = `sudo -S -p '' sh -c ${shq(full)}`;
  if (cwd) full = `cd ${shq(cwd)} && ${full}`;
  return full;
}

function cap(s) {
  return { text: s.slice(0, MAX_OUTPUT), truncated: s.length > MAX_OUTPUT };
}

// ssh2 mkdir(path, attrs, cb) has no recursive option, so ensure each
// missing level explicitly. Any stat error is treated as "does not exist",
// then each level is created while ignoring EEXIST (ssh2 status code 4).
// The root "/" is always assumed to exist and is never created.
function mkdirp(sftp, dir) {
  return new Promise((resolve, reject) => {
    if (dir === '/' || dir === '') return resolve();
    sftp.stat(dir, (e) => {
      if (!e) return resolve();
      const parent = path.posix.dirname(dir);
      if (parent === '/' || parent === dir) return mkdirNow();
      mkdirp(sftp, parent).then(mkdirNow, reject);
    });
    function mkdirNow() {
      sftp.mkdir(dir, (e2) => (e2 && e2.code !== 4 ? reject(e2) : resolve()));
    }
  });
}

// Resolves { content, size, truncated, error }. Read failures are returned
// rather than swallowed so callers can tell "no new data" from "broken".
function readFrom(sftp, file, offset) {
  return new Promise((resolve) => {
    sftp.open(file, 'r', (e, h) => {
      if (e) return resolve({ content: '', size: offset, truncated: false, error: e });
      // The handle is closed on every path: a caller may loop this over one
      // SFTP session (background log polling does), and leaked handles would
      // accumulate on both ends.
      const done = (result) => sftp.close(h, () => resolve(result));
      sftp.fstat(h, (e2, st) => {
        if (e2) return done({ content: '', size: offset, truncated: false, error: e2 });
        // If the file shrank (rotated/truncated) below our offset, restart
        // from the beginning instead of permanently skipping the new data.
        const start = st.size < offset ? 0 : offset;
        const available = st.size - start;
        // size === 0 is ambiguous: it is an empty file, but it is also what
        // /proc and /sys report for streams that do have content. Read once to
        // find out instead of assuming empty -- a read past the end just comes
        // back with 0 bytes.
        const n = available > 0 ? Math.min(available, MAX_OUTPUT) : MAX_OUTPUT;
        const buf = Buffer.alloc(n);
        sftp.read(h, buf, 0, n, start, (e3, bytes) => {
          // EOF on a stream is a normal end, not an error.
          if (e3 && !(e3.code === 1 || /end of file/i.test(e3.message || ''))) {
            return done({ content: '', size: offset, truncated: false, error: e3 });
          }
          // A non-numeric byte count would poison the caller's offset with NaN.
          const got = !e3 && Number.isFinite(bytes) ? Math.min(bytes, n) : 0;
          done({
            content: buf.subarray(0, got).toString('utf8'),
            size: start + got,
            truncated: available > got,
            error: null,
          });
        });
      });
    });
  });
}

// Wraps an ssh2 SFTP error in a message that names the failure, while keeping
// the numeric status code reachable as .code. Callers need the code to add
// context (is this a directory? is that directory non-empty?) and to decide
// whether a retry or a different call would help.
function sftpError(prefix, err) {
  const wrapped = new Error(`${prefix}: ${describeSftpError(err)}`);
  if (err && typeof err.code !== 'undefined') wrapped.code = err.code;
  wrapped.status = err && typeof err.code === 'number' ? SFTP_STATUS[err.code] : undefined;
  return wrapped;
}

function statRemote(sftp, file) {
  return new Promise((resolve, reject) =>
    sftp.stat(file, (e, st) => (e ? reject(sftpError(`stat ${file}`, e)) : resolve(st)))
  );
}

// lstat does not follow symlinks, which is what deletion needs: stat() on a
// symlink to a directory reports a directory, so the caller would try rmdir
// and get "No such file" instead of unlinking the link.
function lstatRemote(sftp, file) {
  return new Promise((resolve, reject) =>
    sftp.lstat(file, (e, st) => (e ? reject(sftpError(`stat ${file}`, e)) : resolve(st)))
  );
}

function readdirRemote(sftp, dir) {
  return new Promise((resolve, reject) =>
    sftp.readdir(dir, (e, list) => (e ? reject(sftpError(`list_dir ${dir}`, e)) : resolve(list)))
  );
}

const S_IFMT = 0o170000;
const S_IFDIR = 0o040000;
const S_IFLNK = 0o120000;

// Works for ssh2 Stats instances and for plain {mode} objects alike.
function isDirMode(attrs) {
  if (!attrs || typeof attrs.mode !== 'number') return false;
  if (typeof attrs.isDirectory === 'function') return attrs.isDirectory();
  return (attrs.mode & S_IFMT) === S_IFDIR;
}
function isLinkMode(attrs) {
  if (!attrs || typeof attrs.mode !== 'number') return false;
  if (typeof attrs.isSymbolicLink === 'function') return attrs.isSymbolicLink();
  return (attrs.mode & S_IFMT) === S_IFLNK;
}

function unlinkRemote(sftp, file) {
  return new Promise((resolve, reject) =>
    sftp.unlink(file, (e) => (e ? reject(sftpError(`delete ${file}`, e)) : resolve()))
  );
}

function rmdirRemote(sftp, dir) {
  return new Promise((resolve, reject) =>
    sftp.rmdir(dir, (e) => (e ? reject(sftpError(`delete ${dir}`, e)) : resolve()))
  );
}

function renameRemote(sftp, from, to) {
  return new Promise((resolve, reject) =>
    sftp.rename(from, to, (e) => (e ? reject(sftpError(`rename ${from} -> ${to}`, e)) : resolve()))
  );
}

// Reads a file as raw bytes, capped. readFrom() decodes as utf8 and would
// corrupt a PNG, so binary transfers get their own path.
function readBinary(sftp, file) {
  return new Promise((resolve, reject) => {
    sftp.open(file, 'r', (e, h) => {
      if (e) return reject(sftpError(`read ${file}`, e));
      const done = (fn) => sftp.close(h, () => fn());
      sftp.fstat(h, (e2, st) => {
        if (e2) return done(() => reject(sftpError(`stat ${file}`, e2)));
        if (st.size > MAX_OUTPUT * 4) {
          return done(() => reject(new Error(`read ${file}: ${st.size} bytes exceeds the binary read limit`)));
        }
        const buf = Buffer.alloc(Math.max(1, st.size));
        // A single SFTP read returns at most one packet (~64 KiB) and reports
        // that short count as success, so a larger file came back silently
        // truncated -- screenshots past 64 KiB lost their JPEG EOI marker.
        // Loop until the declared size is filled.
        const CHUNK = 32768;
        let off = 0;
        const pump = () => {
          if (off >= st.size) return done(() => resolve(buf.subarray(0, off)));
          const len = Math.min(CHUNK, st.size - off);
          sftp.read(h, buf, off, len, off, (e3, bytes) => {
            if (e3) return done(() => reject(sftpError(`read ${file}`, e3)));
            if (!bytes) return done(() => resolve(buf.subarray(0, off)));
            off += bytes;
            pump();
          });
        };
        pump();
      });
    });
  });
}

function imageMime(buf) {
  return buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))
    ? 'image/png'
    : 'image/jpeg';
}

// Depth-first removal used by deletePath({recursive:true}). Symlinks are
// unlinked, never followed -- following one could delete files outside the tree
// the caller asked to remove.
async function removeTree(sftp, dir) {
  const list = await readdirRemote(sftp, dir);
  for (const e of list) {
    if (e.filename === '.' || e.filename === '..') continue;
    const full = path.posix.join(dir, e.filename);
    if (isDirMode(e.attrs)) await removeTree(sftp, full);
    else await unlinkRemote(sftp, full);
  }
  await rmdirRemote(sftp, dir);
}

// fastGet's read loop is bounded by the file size it works from, so handing it
// the size we already checked turns the limit into a hard ceiling: a remote
// that lied in stat() still cannot push more than that many bytes. (ssh2
// honours options.fileSize but leaves it out of its documented option list.)
function fastGetInto(sftp, remotePath, localPath, size) {
  return new Promise((resolve, reject) => {
    const opts = size > 0 ? { fileSize: size } : {};
    sftp.fastGet(remotePath, localPath, opts, (e) =>
      e ? reject(sftpError('download', e)) : resolve()
    );
  });
}

// Best-effort kill of the whole process tree after a timeout. The pid file
// holds the PID of the `bash -c` wrapper that runs the command; recursively
// SIGKILL every descendant, then the wrapper itself. (setsid is NOT used:
// util-linux setsid forks, which both swallows the exit code and redirects
// stdin to /dev/null when it is not a tty.)
function killProcessGroup(client, pidFile) {
  return new Promise((resolve) => {
    let done = false;
    const guard = setTimeout(() => { if (!done) { done = true; resolve(); } }, 3000);
    const finish = () => { if (done) return; done = true; clearTimeout(guard); resolve(); };
    const script = `pid=$(cat ${pidFile} 2>/dev/null || true); ` +
      `kill_children() { local p; for p in $(pgrep -P "$1" 2>/dev/null); do kill_children "$p"; kill -9 "$p" 2>/dev/null; done; }; ` +
      `[ -n "$pid" ] && { kill_children "$pid"; kill -9 "$pid" 2>/dev/null; }; rm -f ${pidFile}; true`;
    client.exec(`bash -c ${shq(script)}`, (err, ch) => {
      if (err) return finish();
      ch.on('exit', finish);
      ch.on('close', finish);
      ch.on('error', finish);
    });
  });
}

function defaultClientFactory(opts = {}) {
  return new Client(opts);
}

// A socket ssh2 will use instead of creating its own, so Nagle can be disabled
// before the handshake. Windows' Nagle + delayed-ACK interaction costs ~170 ms
// per round trip on this workload. ssh2 assumes a supplied socket is already
// connected, so connect it here and hand it over once the TCP handshake lands.
function connectSocket(host, port) {
  return new Promise((resolve, reject) => {
    const sock = new net.Socket();
    sock.setNoDelay(true);
    // Keep an idle pooled connection alive instead of letting the server or a
    // NAT drop it between agent turns.
    sock.setKeepAlive(true, 30000);
    sock.once('connect', () => {
      sock.removeListener('error', reject);
      resolve(sock);
    });
    sock.once('error', reject);
    sock.connect({ host, port });
  });
}

function createBridge(cfg, { clientFactory = defaultClientFactory, configFile = configPath() } = {}) {
  const conns = new Map();
  const sftps = new Map();
  const tasks = new Map();
  const hostKeys = createKnownHostsStore(knownHostsPaths(cfg, configFile));

  // sshd counts concurrent channels per connection (MaxSessions, 10 by default)
  // and resets the whole connection when it is exceeded -- one burst of parallel
  // tool calls could take the bridge down for every caller, not just the ones
  // over the line. A semaphore keeps us under the cap. Only the channel setup is
  // serialised; commands still run concurrently.
  const MAX_CHANNELS = cfg.maxConcurrentChannels || 8;
  let freeSlots = MAX_CHANNELS;
  const channelWaiters = [];
  function acquireChannel() {
    if (freeSlots > 0) {
      freeSlots--;
      return Promise.resolve();
    }
    return new Promise((resolve) => channelWaiters.push(resolve));
  }
  function releaseChannel() {
    const next = channelWaiters.shift();
    // The waiter inherits the slot that was just freed; do not touch freeSlots.
    if (next) next();
    else freeSlots++;
  }

  // A wedged connection (channels exhausted by a background job or a past leak)
  // only recovers by dropping the TCP connection so the server frees every
  // session. dispose() closes it and drops it from the pool; withRetry rebuilds
  // once on a fresh conn.
  //
  // sshd caps concurrent channels per connection (MaxSessions, 10 by default).
  // Going past it does not produce one tidy error: the same condition has been
  // observed as an explicit channel-open failure, a bare "Unable to exec", a
  // channel that closes mid-command, and a server that simply stops answering.
  // All of them mean "reconnect", so all of them are matched here.
  function isChannelFailure(err) {
    const m = (err && err.message) || '';
    return /channel open|open failed|unable to exec|no response from server|connection closed before command completed|session closed|not connected/i.test(m);
  }
  function dispose(name) {
    dropSftp(name);
    const p = conns.get(name);
    if (!p) return;
    conns.delete(name);
    p.then((c) => { try { c.end(); } catch (_) {} }).catch(() => {});
  }
  async function withRetry(name, fn) {
    // Channel exhaustion is transient: the server frees the sessions when the
    // connection drops. One immediate rebuild is not always enough under a
    // burst, so back off and try a few times before surfacing the error.
    let lastErr;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        return await fn();
      } catch (err) {
        if (!isChannelFailure(err)) throw err;
        lastErr = err;
        dispose(name);
        await new Promise((r) => setTimeout(r, 100 * 2 ** attempt));
      }
    }
    throw lastErr;
  }

  function getConn(name) {
    if (conns.has(name)) return conns.get(name);
    const p = (async () => {
      const entry = resolveHost(cfg, name);
      // ssh2 creates its own socket and never disables Nagle. On Windows that
      // combination (Nagle + delayed ACK) puts a ~170 ms stall on every small
      // request/response: 20 serial SFTP ops measured 3363 ms with it and 34 ms
      // without. Each tool call issues several round trips, so this is the
      // single biggest latency fix in the bridge. Tests inject clientFactory
      // and get no socket, so the fakes keep working.
      const sock = clientFactory === defaultClientFactory
        ? await connectSocket(entry.host, entry.port)
        : undefined;
      return await new Promise((resolve, reject) => {
        const client = clientFactory({ sock });
        let ready = false;
        // hostVerifier has no error channel, so a rejection reason is parked here
        // and surfaced through the 'error' event that follows it. Without this the
        // user only sees ssh2's generic "Host denied (verification failed)".
        let hostKeyFailure = null;
        client.on('ready', () => { ready = true; resolve(client); });
        client.on('error', (err) => reject(new Error(`SSH connection to ${entry.name} failed: ${hostKeyFailure || err.message}`)));
        // A connection that closes is dead: if it never became ready the pending
        // promise must not hang, and once ready the pool must drop it so the
        // next call rebuilds instead of reusing a stale client.
        client.on('close', () => {
          if (!ready) reject(new Error(`SSH connection to ${entry.name} closed before ready`));
          if (conns.get(name) === p) conns.delete(name);
        });
        client.connect({
          host: entry.host,
          port: entry.port,
          username: entry.user,
          password: entry.password,
          readyTimeout: 15000,
          sock,
          algorithms: connectAlgorithms(cfg),
          // ssh2 auto-accepts whatever host key answers unless this is set, which
          // would hand the password to an impersonator on the LAN.
          hostVerifier: (blob) => {
            const verdict = verifyHostKey({
              store: hostKeys,
              policy: entry.hostKeyPolicy,
              host: entry.host,
              port: entry.port,
              blob,
              label: entry.name,
              pinnedFingerprint: entry.hostKeyFingerprint,
            });
            if (!verdict.ok) hostKeyFailure = verdict.message;
            return verdict.ok;
          },
        });
      });
    })().catch((err) => {
      conns.delete(name);
      throw err;
    });
    conns.set(name, p);
    return p;
  }

  // One cached SFTP session per host. Opening one per call burned a channel and
  // a round trip on every file operation; on a long agent session that is both
  // slow and a MaxSessions risk. The session is reused until an operation on it
  // fails, at which point withSftp() drops it and retries once on a fresh one.
  async function getSftp(name) {
    if (sftps.has(name)) return sftps.get(name);
    const client = await getConn(name);
    // Opening an SFTP session is a channel open too, so it waits for a slot --
    // but only while being created: the session is cached and long-lived, so
    // holding the slot afterwards would starve every exec call.
    await acquireChannel();
    const p = new Promise((resolve, reject) =>
      client.sftp((e, s) => {
        releaseChannel();
        return e ? reject(e) : resolve(s);
      })
    );
    sftps.set(name, p);
    p.catch(() => { if (sftps.get(name) === p) sftps.delete(name); });
    return p;
  }

  function dropSftp(name) {
    const p = sftps.get(name);
    if (!p) return;
    sftps.delete(name);
    p.then((s) => { try { s.end(); } catch (_) {} }).catch(() => {});
  }

  // Runs fn(sftp) and, if the session itself turns out to be dead, rebuilds it
  // once. Only the SFTP-level failure triggers this; ordinary errors (a missing
  // file, a permission denial) are passed straight through.
  async function withSftp(name, fn) {
    try {
      return await fn(await getSftp(name));
    } catch (err) {
      if (!isSftpSessionFailure(err)) throw err;
      dropSftp(name);
      return fn(await getSftp(name));
    }
  }

  function execChannel(client, { command, cwd, timeoutMs, sudo, pty, env, input, pipefail, sudoPassword }) {
    // Every non-pty command runs through `bash -c` so a timeout can kill the
    // whole process tree via killProcessGroup. setsid is avoided entirely:
    // util-linux setsid forks, which swallows the exit code and redirects
    // stdin to /dev/null when it isn't a tty. The wrapper records its own PID
    // ($$) to a file; killProcessGroup then recursively SIGKILLs descendants.
    // pty commands cannot be double-wrapped (the SSH server already makes them
    // session/process-group leaders, and re-setsid would EPERM); their timeout
    // keeps ch.signal('SIGKILL') (top shell only — accepted limitation).
    const wrap = !pty;
    const pidFile = wrap ? `/tmp/ssh-bridge-pid-${crypto.randomBytes(6).toString('hex')}` : null;
    let full;
    if (wrap) {
      const inner = makeExecCommand({ command, cwd, sudo, env, pipefail });
      const capture = `echo $$ > ${pidFile}; trap 'rm -f ${pidFile}' EXIT;\n`;
      full = `bash -c ${shq(capture + inner)}`;
    } else {
      // pty: no extra wrapper (EPERM), apply cwd/sudo directly.
      full = makeExecCommand({ command, cwd, sudo, env, pipefail });
    }
    const opts = {};
    if (pty) opts.pty = { rows: 40, cols: 200, term: 'xterm-256color' };
    const timeout = timeoutMs || 30000;
    return new Promise((resolve, reject) => {
      // The slot is held from just before the channel opens until the command
      // finishes, on every exit path.
      let slotHeld = false;
      const releaseSlot = () => { if (slotHeld) { slotHeld = false; releaseChannel(); } };
      const finish = (res) => {
        releaseSlot();
        if (res) {
          let out = res.stdout;
          let errOut = res.stderr;
          if (pty) {
            out = stripAnsi(out.replace(/\r/g, ''));
            errOut = stripAnsi(errOut.replace(/\r/g, ''));
          }
          const cOut = cap(out);
          const cErr = cap(errOut);
          resolve({
            exitCode: res.exitCode,
            stdout: cOut.text,
            stderr: cErr.text,
            timedOut: res.timedOut,
            // Accumulation already caps in-flight, so cap() may see text of
            // exactly MAX_OUTPUT and miss the truncation; keep the flag set
            // during accumulation as well.
            truncated: res.truncated === true || cOut.truncated || cErr.truncated,
          });
        } else {
          reject(new Error('connection closed before command completed'));
        }
      };
      // Acquire a channel slot first: sshd's MaxSessions (10 by default) counts
      // concurrent channels per connection, and exceeding it resets the whole
      // connection rather than failing one call.
      acquireChannel().then(() => {
        slotHeld = true;
        // client.exec throws synchronously when the connection is already gone
        // ("Not connected"), so it cannot be left to the callback.
        try {
          client.exec(full, opts, onChannel);
        } catch (e) {
          releaseSlot();
          reject(e);
        }
        function onChannel(err, ch) {
          if (err) {
            releaseSlot();
            return reject(new Error(`exec failed: ${err.message}`));
          }
          let stdout = '';
          let stderr = '';
          let stdoutTruncated = false;
          let stderrTruncated = false;
          let exitCode = null;
          let timedOut = false;
          let done = false;
          let bgGrace = null;
          // Bound accumulation now so runaway output (e.g. `yes`) cannot grow
          // stdout/stderr without limit and OOM the server before capping.
          const append = (cur, chunk, markTruncated) => {
            if (cur.length >= MAX_OUTPUT) { markTruncated(); return cur; }
            if (cur.length + chunk.length > MAX_OUTPUT) {
              markTruncated();
              return cur + chunk.slice(0, MAX_OUTPUT - cur.length);
            }
            return cur + chunk;
          };
          const timer = setTimeout(() => {
            timedOut = true;
            done = true;
            if (pidFile) {
              killProcessGroup(client, pidFile).then(() => {
                clearTimeout(timer);
                finish({ exitCode, stdout, stderr, timedOut });
              });
            } else {
              ch.signal('SIGKILL', () => {
                clearTimeout(timer);
                finish({ exitCode, stdout, stderr, timedOut });
              });
            }
          }, timeout);
          ch.on('error', () => {
            if (done) return;
            done = true;
            clearTimeout(timer);
            if (bgGrace) clearTimeout(bgGrace);
            finish(null);
          });
          // Write stdin immediately after the channel is created, NOT on the
          // 'ready' event. ssh2 exec channels accept buffered writes before the
          // open confirmation and flush them once it arrives; the flush callback
          // then closes stdin (EOF). Writing + ending synchronously on 'ready'
          // can drop the buffered data, stranding `cat`/`read`/`sudo -S` on
          // empty stdin. Verified against real OpenSSH.
          if (sudo && sudoPassword) {
            ch.stdin.write(sudoPassword + '\n', () => {
              if (input) ch.stdin.write(input, () => ch.stdin.end());
              else ch.stdin.end();
            });
          } else if (input) {
            ch.stdin.write(input, () => ch.stdin.end());
          } else {
            ch.stdin.end();
          }
          ch.on('exit', (code) => {
            exitCode = code;
            // The foreground process is done. If a background job (`nohup ... &`)
            // still holds the channel's stdio open, 'close' never arrives and the
            // tool would block until it times out. Start a short countdown so we
            // finish as a normal result (NOT a timeout, nothing is killed) when
            // the channel is only being held by a detached child.
            if (bgGrace == null) {
              bgGrace = setTimeout(() => {
                if (done) return;
                done = true;
                clearTimeout(timer);
                finish({ exitCode, stdout, stderr, timedOut: false, truncated: stdoutTruncated || stderrTruncated });
              }, BG_GRACE_MS);
            }
          });
          ch.on('data', (d) => { stdout = append(stdout, d.toString(), () => { stdoutTruncated = true; }); });
          ch.stderr.on('data', (d) => { stderr = append(stderr, d.toString(), () => { stderrTruncated = true; }); });
          ch.on('close', (code) => {
            if (done) return;
            done = true;
            clearTimeout(timer);
            if (bgGrace) clearTimeout(bgGrace);
            if (exitCode == null) exitCode = code;
            // A close without an exit code and without a timeout means the
            // connection died mid-command; that is a failure, not a success
            // with a null exit code. `== null` also covers code === undefined.
            if (exitCode == null && !timedOut) return finish(null);
            finish({ exitCode, stdout, stderr, timedOut, truncated: stdoutTruncated || stderrTruncated });
          });
        }
      }, reject);
    });
  }

  function runCommand(name, args) {
    const entry = resolveHost(cfg, name);
    // Resolve the connection *after* the slot is granted: waiting on the
    // semaphore can outlive the connection it was queued behind, and using a
    // disposed client fails with "Not connected" instead of retrying.
    return withRetry(entry.name, async () => {
      const client = await getConn(entry.name);
      return execChannel(client, { ...args, sudoPassword: entry.sudoPassword });
    });
  }

  function listHosts() {
    return Object.entries(cfg.hosts).map(([name, h]) => ({
      name,
      host: h.host,
      port: h.port,
      user: h.user,
    }));
  }

  function listDir(name, dir) {
    return withRetry(name, () => withSftp(name, async (s) => {
      let list;
      try {
        list = await readdirRemote(s, dir);
      } catch (err) {
        // SFTP answers OPENDIR on a regular file with NO_SUCH_FILE (2), which
        // reads as "the path is wrong" even though the path exists and is just
        // a file. Check and say so.
        if (err.code === 2) {
          const st = await statRemote(s, dir).catch(() => null);
          if (st && !isDirMode(st)) {
            throw new Error(`list_dir ${dir}: NOT_A_DIRECTORY (the path exists and is a ${isLinkMode(st) ? 'symlink' : 'file'})`);
          }
        }
        throw err;
      }

      const entries = list
        .filter((e) => e.filename !== '.' && e.filename !== '..')
        .map((e) => ({
          name: e.filename,
          type: isDirMode(e.attrs) ? 'dir' : isLinkMode(e.attrs) ? 'link' : 'file',
          size: e.attrs.size,
          mtime: e.attrs.mtime ? new Date(e.attrs.mtime * 1000).toISOString() : null,
          mode: e.attrs.mode ? '0' + (e.attrs.mode & 0o777).toString(8) : null,
        }))
        .sort((a, b) => (a.type === b.type ? a.name.localeCompare(b.name) : a.type === 'dir' ? -1 : b.type === 'dir' ? 1 : 0));
      return { path: dir, count: entries.length, entries };
    }));
  }

  // Deletion is the one destructive operation, so it is explicit about what it
  // did: a missing path is reported, not silently treated as success, and a
  // non-empty directory is never removed implicitly.
  async function deletePath(name, target, { recursive = false } = {}) {
    return withRetry(name, () => withSftp(name, async (s) => {
      // lstat, not stat: a symlink must be unlinked as a link, never resolved.
      // Resolving it would rmdir the *target* directory.
      const st = await lstatRemote(s, target);
      if (isLinkMode(st)) {
        await unlinkRemote(s, target);
        return { ok: true, removed: 'link' };
      }
      if (isDirMode(st)) {
        if (recursive) {
          await removeTree(s, target);
          return { ok: true, removed: 'dir', recursive: true };
        }
        // SFTP has no ENOTEMPTY status: removing a non-empty directory comes
        // back as the generic FAILURE (4), which tells an agent nothing.
        try {
          await rmdirRemote(s, target);
        } catch (err) {
          if (err.code === 4) {
            throw new Error(
              `delete ${target}: DIRECTORY_NOT_EMPTY (SFTP returned FAILURE); pass recursive: true to remove the tree`
            );
          }
          throw err;
        }
        return { ok: true, removed: 'dir' };
      }
      await unlinkRemote(s, target);
      return { ok: true, removed: 'file' };
    }));
  }

  async function renamePath(name, from, to) {
    return withRetry(name, () => withSftp(name, async (s) => {
      await mkdirp(s, path.posix.dirname(to));
      await renameRemote(s, from, to);
      return { ok: true, from, to };
    }));
  }

  // Search file contents on the remote host. Prefers ripgrep (fast, respects
  // .gitignore, has --glob) and falls back to grep -r. Patterns are shell-quoted,
  // so the model's text never becomes shell syntax.
  function searchFiles(name, { pattern, path: dir = '.', glob, maxResults = 100, ignoreCase = false, fixed = false }) {
    if (!pattern) throw new Error('search_files requires a pattern');
    const entry = resolveHost(cfg, name);
    const max = Math.max(1, Math.min(maxResults, 1000));
    const rgArgs = ['--color=never', '--line-number', '--no-heading', '--with-filename'];
    if (ignoreCase) rgArgs.push('--ignore-case');
    if (fixed) rgArgs.push('--fixed-strings');
    if (glob) rgArgs.push('--glob', glob);
    rgArgs.push('--max-count', String(max), '--', pattern, dir);
    const cmd = `if command -v rg >/dev/null 2>&1; then rg ${rgArgs.map(shq).join(' ')}; else ` +
      `grep ${[
        '-r', '--color=never', '--line-number', '--with-filename',
        ignoreCase ? '--ignore-case' : null,
        fixed ? '--fixed-strings' : null,
        `--max-count=${max}`,
        '--exclude-dir=.git',
        '--', pattern, dir,
      ].filter(Boolean).map(shq).join(' ')}; fi`;
    return withRetry(entry.name, async () => {
      const r = await runCommand(entry.name, { command: cmd, timeoutMs: 60000 });
      // grep and ripgrep both use 0 = matches, 1 = none, 2 = error.
      if (r.exitCode === 1) return { matches: [], count: 0 };
      if (r.exitCode === 2 || r.exitCode !== 0) {
        // The message grep prints for a bad path is localized (zh_CN gives
        // "没有那个文件或目录"), so it is useless to a caller matching on it.
        // Establish the cause with a locale-independent check instead.
        const probe = await runCommand(entry.name, {
          command: `test -e ${shq(dir)} && echo exists || echo missing`,
          timeoutMs: 10000,
        });
        if (probe.stdout.trim() === 'missing') {
          throw new Error(`search_files: path does not exist: ${dir}`);
        }
        throw new Error(`search_files: search failed in ${dir} (exit ${r.exitCode})`);
      }
      const all = r.stdout.split(/\r?\n/).filter(Boolean).map((line) => {
        const m = line.match(/^(.*?):(\d+):(.*)$/);
        return m ? { file: m[1], line: Number(m[2]), text: m[3] } : { file: null, line: null, text: line };
      });
      return {
        matches: all.slice(0, max),
        count: Math.min(all.length, max),
        truncated: r.truncated === true || all.length > max,
      };
    });
  }

  function readFile(name, file) {
    return withRetry(name, () => withSftp(name, async (s) => {
      const r = await readFrom(s, file, 0);
      if (r.error) {
        // SFTP reports OPENDIR/OPEN on a directory as the generic FAILURE (4),
        // so name the actual cause before falling back to the status code.
        if (r.error.code === 4) {
          const st = await statRemote(s, file).catch(() => null);
          if (st && isDirMode(st)) throw new Error(`read_file ${file}: IS_A_DIRECTORY (use list_dir)`);
        }
        throw new Error(`read_file ${file}: ${describeSftpError(r.error)}`);
      }
      // sftp.readFile pulls the whole file into memory with no bound, so a
      // prompt-injected path (say /var/log/huge.log) could OOM the server.
      // The tool is documented as small-text-files only.
      if (r.truncated) {
        throw new Error(
          `read_file ${file}: not read completely -- the file exceeds the ${MAX_OUTPUT}-byte limit for read_file; use download for large files`
        );
      }
      return { content: r.content };
    }));
  }

  async function writeRemoteFile(sftp, file, content) {
    const dir = path.posix.dirname(file);
    await mkdirp(sftp, dir);
    await new Promise((resolve, reject) =>
      sftp.writeFile(file, content, (e) =>
        e ? reject(sftpError(`write_file ${file}`, e)) : resolve()
      )
    );
  }

  function writeFile(name, file, content) {
    return withRetry(name, () => withSftp(name, async (s) => {
      await writeRemoteFile(s, file, content);
      return { ok: true };
    }));
  }

  // async so a policy rejection arrives as a rejected promise like every other
  // bridge method, rather than throwing synchronously out of the call.
  async function upload(name, localPath, remotePath) {
    const local = checkLocalPath({ localPath, cfg, configFile, tool: 'upload' });
    return withRetry(name, () => withSftp(name, async (s) => {
      await mkdirp(s, path.posix.dirname(remotePath));
      await new Promise((resolve, reject) =>
        s.fastPut(local, remotePath, (e) =>
          e ? reject(sftpError('upload', e)) : resolve()
        )
      );
      return { ok: true };
    }));
  }

  async function download(name, remotePath, localPath) {
    const local = checkLocalPath({ localPath, cfg, configFile, tool: 'download' });
    const limit = downloadLimit(cfg);
    return withRetry(name, () => withSftp(name, async (s) => {
      const st = await statRemote(s, remotePath);
      // Checked before a byte moves: a hostile or broken remote could
      // otherwise stream until the local disk is full.
      if (limit > 0 && st.size > limit) {
        throw new Error(
          `download ${remotePath}: ${st.size} bytes exceeds maxDownloadBytes (${limit}); ` +
            'raise "maxDownloadBytes" in the server config (0 = unlimited) if the file is legitimate'
        );
      }
      fs.mkdirSync(path.dirname(local), { recursive: true });
      await fastGetInto(s, remotePath, local, st.size);
      // A download that quietly wrote fewer bytes than the file holds is the
      // same class of silent loss this bridge has been fixed for elsewhere.
      if (st.size > 0) {
        const written = fs.statSync(local).size;
        if (written !== st.size) {
          throw new Error(`download ${remotePath}: wrote ${written} of ${st.size} bytes`);
        }
      }
      return { ok: true };
    }));
  }

  function startBackground(name, { command, cwd }) {
    const entry = resolveHost(cfg, name);
    const taskId = crypto.randomBytes(6).toString('hex');
    const scriptFile = `/tmp/ssh-bridge-${taskId}.sh`;
    const outFile = `/tmp/ssh-bridge-${taskId}.out`;
    const pidFile = `/tmp/ssh-bridge-${taskId}.pid`;
    return withRetry(entry.name, async () => {
      await withSftp(entry.name, (s) => writeRemoteFile(s, scriptFile, command));
      // </dev/null + redirected stdio detach the process from the channel so it
      // cannot hold an ssh session open (which would exhaust MaxSessions).
      const run = `cd ${shq(cwd || '.')} && nohup bash ${shq(scriptFile)} > ${outFile} 2>&1 < /dev/null & echo $! > ${pidFile}`;
      const r = await runCommand(entry.name, { command: run, timeoutMs: 15000 });
      if (r.exitCode !== 0) {
        await runCommand(entry.name, {
          command: `rm -f ${scriptFile} ${outFile} ${pidFile}`,
          timeoutMs: 5000,
        }).catch(() => {});
        throw new Error(`start_background failed: ${r.stderr}`);
      }
      const pidR = await runCommand(entry.name, { command: `cat ${pidFile}`, timeoutMs: 5000 });
      const pid = pidR.stdout.trim();
      if (!/^\d+$/.test(pid)) {
        await runCommand(entry.name, {
          command: `rm -f ${scriptFile} ${outFile} ${pidFile}`,
          timeoutMs: 5000,
        }).catch(() => {});
        throw new Error('start_background failed: could not read process pid');
      }
      tasks.set(taskId, { hostName: entry.name, pid, scriptFile, outFile, pidFile, offset: 0 });
      // The consumers (background_logs / stop_background) take `task_id`, and so
      // does the README. Returning camelCase here made an agent that copied the
      // key straight back fail MCP input validation.
      return { task_id: taskId, taskId, pid };
    });
  }

  function backgroundLogs(taskId) {
    const t = tasks.get(taskId);
    if (!t) throw new Error(`unknown task_id ${taskId}`);
    return withRetry(t.hostName, async () => {
      const r = await withSftp(t.hostName, (s) => readFrom(s, t.outFile, t.offset));
      // A log file that does not exist yet still means "no output", as before;
      // any other read failure must not be reported as an idle task.
      if (r.error && !isNoSuchFile(r.error)) {
        throw new Error(`background_logs ${taskId}: ${r.error.message}`);
      }
      // Advance only past bytes actually returned. When the per-call read is
      // capped, the next poll picks up where this one stopped instead of
      // dropping the difference.
      if (!r.error) t.offset = r.size;
      const alive = await runCommand(t.hostName, { command: `kill -0 ${t.pid} 2>/dev/null || true`, timeoutMs: 5000 });
      // truncated means the producer outran us: poll again for the remainder.
      return { content: r.content, running: alive.exitCode === 0, truncated: r.truncated === true };
    });
  }

  async function screenshot(name, { maxWidth = 1600, quality = 82 } = {}) {
    const entry = resolveHost(cfg, name);
    const remotePath = `/tmp/ssh-bridge-shot-${crypto.randomBytes(6).toString('hex')}.png`;
    const optimizedPath = remotePath.replace(/\.png$/, '.jpg');
    return withRetry(entry.name, async () => {
      // The capture script goes in over stdin (`bash -s`) rather than as a
      // `bash -c` argument: the script contains single quotes, and quoting it
      // into a shell word leaves bash parsing the inner quotes, which shifts
      // $0/$1 and silently loses the session detection. Paths stay arguments.
      const r = await runCommand(entry.name, {
        command: `bash -s ${shq(remotePath)}`,
        input: buildCaptureScript(),
        timeoutMs: 90000,
      });
      const result = parseCaptureResult(r.stdout);
      if (!result.ok) throw new Error(`screenshot ${entry.name}: ${result.error}`);

      let readPath = remotePath;
      let data;
      try {
        // Shrink before transferring: a full desktop PNG is ~1.7 MB and the
        // same frame at 1600px/quality 82 is ~30 KB.
        if (maxWidth > 0) {
          const o = await runCommand(entry.name, {
            command: `bash -s ${shq(remotePath)} ${shq(optimizedPath)} ${shq(String(maxWidth))} ${shq(String(quality))}`,
            input: buildOptimizeScript(),
            timeoutMs: 30000,
          });
          if (String(o.stdout).includes('OPTIMIZED')) readPath = optimizedPath;
        }
        data = await withSftp(entry.name, (s) => readBinary(s, readPath));
      } finally {
        runCommand(entry.name, {
          command: `rm -f ${shq(remotePath)} ${shq(optimizedPath)}`,
          timeoutMs: 5000,
        }).catch(() => {});
      }
      if (!looksLikeImage(data)) {
        throw new Error(
          `screenshot ${entry.name}: capture reported success via ${result.tool} but the file is not a ` +
            'valid image (a blank or zero-filled capture usually means the tool could not reach the display)'
        );
      }
      return {
        mimeType: imageMime(data),
        base64: data.toString('base64'),
        bytes: data.length,
        optimized: readPath === optimizedPath,
        tool: result.tool,
        sessionType: result.sessionType,
        display: result.display,
      };
    });
  }

  async function stopBackground(taskId) {
    const t = tasks.get(taskId);
    if (!t) throw new Error(`unknown task_id ${taskId}`);
    await runCommand(t.hostName, { command: `kill -9 ${t.pid} 2>/dev/null || true`, timeoutMs: 5000 });
    await runCommand(t.hostName, {
      command: `rm -f ${t.scriptFile} ${t.outFile} ${t.pidFile}`,
      timeoutMs: 5000,
    }).catch(() => {});
    tasks.delete(taskId);
    return { ok: true };
  }

  return {
    listHosts,
    runCommand,
    readFile,
    writeFile,
    listDir,
    deletePath,
    renamePath,
    searchFiles,
    upload,
    download,
    screenshot,
    startBackground,
    backgroundLogs,
    stopBackground,
  };
}

module.exports = {
  createBridge,
  makeExecCommand,
  stripAnsi,
  mkdirp,
  killProcessGroup,
  isNoSuchFile,
  readFrom,
  readBinary,
  statRemote,
  readdirRemote,
  removeTree,
  isDirMode,
  isLinkMode,
  describeSftpError,
  SFTP_STATUS,
  connectAlgorithms,
  downloadLimit,
  SHA1_REMOVALS,
  DEFAULT_MAX_DOWNLOAD,
  MAX_OUTPUT,
};
