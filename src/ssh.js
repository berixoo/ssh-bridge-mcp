const { Client } = require('ssh2');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { resolveHost, knownHostsPaths, configPath } = require('./config');
const { createKnownHostsStore, verifyHostKey } = require('./hostkeys');
const { checkLocalPath } = require('./paths');

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

function shq(s) {
  return "'" + s.replace(/'/g, `'\\''`) + "'";
}

function makeExecCommand({ command, cwd, sudo, env }) {
  let full = command;
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
        if (available <= 0) return done({ content: '', size: st.size, truncated: false, error: null });
        // Cap the per-call read. Buffer.alloc(available) lets a runaway
        // producer -- or an fstat that simply lies -- allocate unbounded memory
        // in the server process.
        const n = Math.min(available, MAX_OUTPUT);
        const buf = Buffer.alloc(n);
        sftp.read(h, buf, 0, n, start, (e3, bytes) => {
          if (e3) return done({ content: '', size: offset, truncated: false, error: e3 });
          // A non-numeric byte count would poison the caller's offset with NaN.
          const got = Number.isFinite(bytes) ? Math.min(bytes, n) : 0;
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

function statRemote(sftp, file) {
  return new Promise((resolve, reject) =>
    sftp.stat(file, (e, st) => (e ? reject(new Error(`stat ${file}: ${e.message}`)) : resolve(st)))
  );
}

// fastGet's read loop is bounded by the file size it works from, so handing it
// the size we already checked turns the limit into a hard ceiling: a remote
// that lied in stat() still cannot push more than that many bytes. (ssh2
// honours options.fileSize but leaves it out of its documented option list.)
function fastGetInto(sftp, remotePath, localPath, size) {
  return new Promise((resolve, reject) => {
    const opts = size > 0 ? { fileSize: size } : {};
    sftp.fastGet(remotePath, localPath, opts, (e) =>
      e ? reject(new Error(`download: ${e.message}`)) : resolve()
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

function createBridge(cfg, { clientFactory = () => new Client(), configFile = configPath() } = {}) {
  const conns = new Map();
  const tasks = new Map();
  const hostKeys = createKnownHostsStore(knownHostsPaths(cfg, configFile));

  // A wedged connection (channels exhausted by a background job or a past leak)
  // only recovers by dropping the TCP connection so the server frees every
  // session. dispose() closes it and drops it from the pool; isChannelFailure
  // matches ssh2's exact message; withRetry rebuilds once on a fresh conn.
  function isChannelFailure(err) {
    return /channel open|open failed/i.test((err && err.message) || '');
  }
  function dispose(name) {
    const p = conns.get(name);
    if (!p) return;
    conns.delete(name);
    p.then((c) => { try { c.end(); } catch (_) {} }).catch(() => {});
  }
  async function withRetry(name, fn) {
    try {
      return await fn();
    } catch (err) {
      if (!isChannelFailure(err)) throw err;
      dispose(name);
      return await fn();
    }
  }

  function getConn(name) {
    if (conns.has(name)) return conns.get(name);
    const p = new Promise((resolve, reject) => {
      const entry = resolveHost(cfg, name);
      const client = clientFactory({});
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
    }).catch((err) => {
      conns.delete(name);
      throw err;
    });
    conns.set(name, p);
    return p;
  }

  async function getSftp(name) {
    const client = await getConn(name);
    return new Promise((resolve, reject) =>
      client.sftp((e, s) => (e ? reject(e) : resolve(s)))
    );
  }

  function execChannel(client, { command, cwd, timeoutMs, sudo, pty, env, input, sudoPassword }) {
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
      const inner = makeExecCommand({ command, cwd, sudo, env });
      const capture = `echo $$ > ${pidFile}; trap 'rm -f ${pidFile}' EXIT;\n`;
      full = `bash -c ${shq(capture + inner)}`;
    } else {
      // pty: no extra wrapper (EPERM), apply cwd/sudo directly.
      full = makeExecCommand({ command, cwd, sudo, env });
    }
    const opts = {};
    if (pty) opts.pty = { rows: 40, cols: 200, term: 'xterm-256color' };
    const timeout = timeoutMs || 30000;
    return new Promise((resolve, reject) => {
      const finish = (res) => {
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
      client.exec(full, opts, (err, ch) => {
        if (err) return reject(new Error(`exec failed: ${err.message}`));
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
      });
    });
  }

  function runCommand(name, args) {
    const entry = resolveHost(cfg, name);
    return withRetry(entry.name, () =>
      getConn(entry.name).then((client) =>
        execChannel(client, { ...args, sudoPassword: entry.sudoPassword })
      )
    );
  }

  function listHosts() {
    return Object.entries(cfg.hosts).map(([name, h]) => ({
      name,
      host: h.host,
      port: h.port,
      user: h.user,
    }));
  }

  function readFile(name, file) {
    return withRetry(name, async () => {
      const s = await getSftp(name);
      try {
        const r = await readFrom(s, file, 0);
        if (r.error) throw new Error(`read_file ${file}: ${r.error.message}`);
        // sftp.readFile pulls the whole file into memory with no bound, so a
        // prompt-injected path (say /var/log/huge.log) could OOM the server.
        // The tool is documented as small-text-files only.
        if (r.truncated) {
          throw new Error(
            `read_file ${file}: not read completely -- the file exceeds the ${MAX_OUTPUT}-byte limit for read_file; use download for large files`
          );
        }
        return { content: r.content };
      } finally {
        try { s.end(); } catch (_) {}
      }
    });
  }

  async function writeRemoteFile(sftp, file, content) {
    const dir = path.posix.dirname(file);
    await mkdirp(sftp, dir);
    await new Promise((resolve, reject) =>
      sftp.writeFile(file, content, (e) =>
        e ? reject(new Error(`write_file ${file}: ${e.message}`)) : resolve()
      )
    );
  }

  function writeFile(name, file, content) {
    return withRetry(name, async () => {
      const s = await getSftp(name);
      try {
        await writeRemoteFile(s, file, content);
        return { ok: true };
      } finally {
        try { s.end(); } catch (_) {}
      }
    });
  }

  // async so a policy rejection arrives as a rejected promise like every other
  // bridge method, rather than throwing synchronously out of the call.
  async function upload(name, localPath, remotePath) {
    const local = checkLocalPath({ localPath, cfg, configFile, tool: 'upload' });
    return withRetry(name, async () => {
      const s = await getSftp(name);
      try {
        await mkdirp(s, path.posix.dirname(remotePath));
        await new Promise((resolve, reject) =>
          s.fastPut(local, remotePath, (e) =>
            e ? reject(new Error(`upload: ${e.message}`)) : resolve()
          )
        );
        return { ok: true };
      } finally {
        try { s.end(); } catch (_) {}
      }
    });
  }

  async function download(name, remotePath, localPath) {
    const local = checkLocalPath({ localPath, cfg, configFile, tool: 'download' });
    const limit = downloadLimit(cfg);
    return withRetry(name, async () => {
      const s = await getSftp(name);
      try {
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
      } finally {
        try { s.end(); } catch (_) {}
      }
    });
  }

  function startBackground(name, { command, cwd }) {
    const entry = resolveHost(cfg, name);
    const taskId = crypto.randomBytes(6).toString('hex');
    const scriptFile = `/tmp/ssh-bridge-${taskId}.sh`;
    const outFile = `/tmp/ssh-bridge-${taskId}.out`;
    const pidFile = `/tmp/ssh-bridge-${taskId}.pid`;
    return withRetry(entry.name, async () => {
      const s = await getSftp(entry.name);
      try {
        await writeRemoteFile(s, scriptFile, command);
      } finally {
        try { s.end(); } catch (_) {}
      }
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
      return { taskId, pid };
    });
  }

  function backgroundLogs(taskId) {
    const t = tasks.get(taskId);
    if (!t) throw new Error(`unknown task_id ${taskId}`);
    return withRetry(t.hostName, async () => {
      const s = await getSftp(t.hostName);
      let r;
      try {
        r = await readFrom(s, t.outFile, t.offset);
      } finally {
        try { s.end(); } catch (_) {}
      }
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
    upload,
    download,
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
  statRemote,
  connectAlgorithms,
  downloadLimit,
  SHA1_REMOVALS,
  DEFAULT_MAX_DOWNLOAD,
  MAX_OUTPUT,
};
