const { Client } = require('ssh2');
const crypto = require('crypto');
const fs = require('fs');
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
      .map(([k, v]) => {
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) throw new Error(`invalid environment variable name: ${k}`);
        return `export ${k}=${shq(String(v))};`;
      })
      .join(' ');
    full = `${exports} ${full}`;
  }
  // sudo and cwd wrap the *current* full string so env exports stay visible
  // to the wrapped command (they run inside the sudo'd shell too).
  if (sudo) full = `sudo -S -p '' bash -c ${shq(full)}`;
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
async function readFrom(sftp, file, offset = 0, limit = MAX_OUTPUT) {
  let handle;
  let start = offset;
  const call = (method, ...args) => new Promise((resolve, reject) => {
    sftp[method](...args, (e, value) => e ? reject(e) : resolve(value));
  });
  try {
    handle = await call('open', file, 'r');
    const st = await call('fstat', handle);
    if (st.size < offset) start = 0;
    const buf = Buffer.alloc(limit + 1);
    let used = 0;
    while (used < buf.length) {
      let count;
      try { count = await call('read', handle, buf, used, Math.min(32768, buf.length - used), start + used); }
      catch (e) { if (e.code === 1 || /end of file/i.test(e.message || '')) break; throw e; }
      if (!Number.isInteger(count) || count < 0 || count > Math.min(32768, buf.length - used)) {
        throw new Error('invalid SFTP byte count');
      }
      if (count === 0) break;
      used += count;
    }
    const buffer = buf.subarray(0, Math.min(used, limit));
    return { buffer, content: buffer.toString('utf8'), size: start + buffer.length, truncated: used > limit || st.size > start + buffer.length, error: null };
  } catch (error) {
    return { buffer: Buffer.alloc(0), content: '', size: offset, truncated: false, error };
  } finally {
    if (handle !== undefined) await call('close', handle).catch(() => {});
  }
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
  if (size === 0) {
    // ssh2 ignores fileSize:0. Probe rather than let a second stat silently
    // remove the ceiling (or mistake a /proc pseudo-file for an empty file).
    return readFrom(sftp, remotePath, 0, 1).then((r) => {
      if (r.error) throw r.error;
      if (r.buffer.length || r.truncated) throw new Error('download: size changed or pseudo-file reports zero; use run_command for streams');
      fs.writeFileSync(localPath, Buffer.alloc(0));
    });
  }
  return new Promise((resolve, reject) => {
    const opts = { fileSize: size };
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

function createBridge(cfg, { clientFactory = defaultClientFactory, configFile = configPath() } = {}) {
  const { createRuntime } = require('./runtime');
  const { createExecutor } = require('./exec');
  const { createSessions } = require('./session');
  const hostKeys = createKnownHostsStore(knownHostsPaths(cfg, configFile));
  const resolveName = (name) => resolveHost(cfg, name).name;
  const runtime = createRuntime({ cfg, configFile, clientFactory,
    realClient: clientFactory === defaultClientFactory,
    resolveHost: (name) => resolveHost(cfg, name), algorithms: connectAlgorithms(cfg),
    verify: (entry, blob) => verifyHostKey({ store: hostKeys, policy: entry.hostKeyPolicy,
      host: entry.host, port: entry.port, blob, label: entry.name, pinnedFingerprint: entry.hostKeyFingerprint }),
  });
  const executor = createExecutor({ runtime, makeExecCommand, killProcessGroup, shq, stripAnsi, maxOutput: MAX_OUTPUT, graceMs: BG_GRACE_MS });
  const sessions = createSessions({ runtime, shq, maxOutput: MAX_OUTPUT });
  const sftps = new Map();
  function dropSftp(name, expected) {
    const rec = expected || sftps.get(name);
    if (!rec || rec.closed) return;
    rec.closed = true;
    if (sftps.get(name) === rec) sftps.delete(name);
    rec.rejectOpen?.(runtime.failure('CONNECTION_CLOSED', 'SFTP session closed during opening'));
    rec.entry?.owners.delete(rec.dispose);
    try { rec.session?.end(); } catch (_) {}
    // The containing transport is closed if an in-flight SFTP operation is
    // ambiguous; no whole-host invalidation or operation replay.
    if (rec.entry && !rec.entry.closing && rec.session && !rec.sessionClosed) runtime.invalidate(rec.entry);
    rec.lease?.release();
  }
  async function getSftp(name) {
    name = resolveName(name);
    const cached = sftps.get(name);
    if (cached) return runtime.wait(cached.ready);
    const rec = { closed: false, ready: null };
    sftps.set(name, rec);
    rec.dispose = () => dropSftp(name, rec);
    rec.ready = (async () => {
      const lease = await runtime.acquire(name);
      rec.lease = lease;
      rec.entry = lease.entry;
      if (rec.closed) { lease.release(); throw new Error('SFTP session closed during opening'); }
      rec.entry.owners.add(rec.dispose);
      const pending = new Promise((resolve, reject) => {
        rec.rejectOpen = reject;
        try {
          rec.entry.client.sftp((err, session) => {
            if (rec.closed) { try { session?.end(); } catch (_) {} return; }
            if (err) return reject(err);
            rec.session = session;
            session.on?.('error', rec.dispose);
            session.on?.('close', () => { rec.sessionClosed = true; rec.dispose(); });
            resolve(session);
          });
        } catch (e) { reject(e); }
      });
      return runtime.wait(pending, () => { runtime.invalidate(rec.entry); rec.dispose(); });
    })().catch((e) => { rec.dispose(); throw e; });
    return runtime.wait(rec.ready);
  }
  async function withSftp(name, fn) {
    name = resolveName(name);
    const s = await getSftp(name);
    const rec = sftps.get(name);
    runtime.check();
    if (!rec || rec.closed || rec.session !== s) throw runtime.failure('CONNECTION_CLOSED', 'SFTP session closed before operation');
    const signal = runtime.context()?.signal;
    const guarded = new Proxy(s, { get(target, key) {
      const value = target[key];
      if (typeof value !== 'function') return value;
      if (['on', 'once', 'removeListener', 'end', 'destroy'].includes(key)) return value.bind(target);
      return (...args) => {
        const callback = args.at(-1);
        if (typeof callback !== 'function') { runtime.check(); return value.apply(target, args); }
        if (signal?.aborted) { queueMicrotask(() => callback(signal.reason)); return; }
        args[args.length - 1] = (...result) => callback(...(signal?.aborted ? [signal.reason] : result));
        return value.apply(target, args);
      };
    } });
    try {
      return await runtime.wait(Promise.resolve().then(() => { runtime.check(); return fn(guarded); }), rec.dispose);
    } catch (e) {
      if (isSftpSessionFailure(e)) rec.dispose();
      throw e;
    }
  }
  // Kept as an execution boundary for existing compound helpers. Deliberately
  // does NOT replay a mutation after a transport error.
  function withRetry(name, fn) { runtime.check(); return fn(); }
  async function runCommand(name, args) {
    name = resolveName(name);
    if (args.session) return sessions.run(name, args);
    const host = resolveHost(cfg, name);
    return executor.run(name, args, host.sudoPassword);
  }
  function closeShell(name) { return sessions.close(resolveName(name)); }

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

  async function writeRemoteFile(sftp, file, content) {
    const dir = path.posix.dirname(file);
    await mkdirp(sftp, dir);
    await new Promise((resolve, reject) =>
      sftp.writeFile(file, content, (e) =>
        e ? reject(sftpError(`write_file ${file}`, e)) : resolve()
      )
    );
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

  const files = require('./files').createFileTools({ withSftp, cfg, configFile, MAX_OUTPUT, mkdirp,
    statRemote, readFrom, sftpError, isDirMode, isLinkMode, checkLocalPath, fastGetInto, wait: runtime.wait });
  const jobs = require('./jobs').createJobManager({ runCommand, withSftp, readFrom, writeRemoteFile, resolveName, shq, wait: runtime.wait, check: runtime.check });
  const tunnels = require('./tunnels').createTunnels({ runtime, resolveName });
  const methods = {
    listHosts, runCommand, listDir, deletePath, renamePath, searchFiles, screenshot,
    closeShell, ...files, ...jobs,
    openTunnel: tunnels.open, listTunnels: tunnels.list, closeTunnel: tunnels.close,
  };
  const bridge = {};
  for (const [key, fn] of Object.entries(methods)) {
    if (key === 'listHosts') { bridge[key] = fn; continue; }
    bridge[key] = (...args) => {
      const options = args.at(-1);
      const invoke = () => {
        if (Object.hasOwn(files, key)) args[0] = resolveName(args[0]);
        return fn(...args);
      };
      return runtime.operation({ ...(options && typeof options === 'object' ? options : {}),
        timeoutMs: options?.timeoutMs ?? (key === 'runCommand' ? 30000 : key === 'screenshot' ? 90000 : 60000) }, invoke);
    };
  }
  bridge.withOperation = runtime.operation;
  bridge.close = async () => {
    sessions.shutdown();
    const closingTunnels = tunnels.shutdown();
    runtime.shutdown();
    await closingTunnels;
  };
  return bridge;
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
