const { Client } = require('ssh2');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { resolveHost } = require('./config');

const MAX_OUTPUT = 500 * 1024;
const ANSI_RE = /\x1b\[[0-9;?]*[A-Za-z]/g;

function stripAnsi(s) {
  return s.replace(ANSI_RE, '');
}

function shq(s) {
  return "'" + s.replace(/'/g, `'\\''`) + "'";
}

function makeExecCommand({ command, cwd, sudo }) {
  let full = command;
  if (sudo) full = `sudo -S -p '' sh -c ${shq(command)}`;
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

// Best-effort kill of the whole process tree after a timeout. The exec command
// is wrapped in `setsid` so the child becomes a session leader whose PID equals
// its process-group id; killing the negative PID reaches every descendant.
function killProcessGroup(client, pidFile) {
  return new Promise((resolve) => {
    let done = false;
    const guard = setTimeout(() => { if (!done) { done = true; resolve(); } }, 2000);
    const finish = () => { if (done) return; done = true; clearTimeout(guard); resolve(); };
    client.exec(`kill -TERM -- -$(cat ${pidFile}) 2>/dev/null || true; rm -f ${pidFile}`, (err, ch) => {
      if (err) return finish();
      ch.on('exit', finish);
      ch.on('close', finish);
      ch.on('error', finish);
    });
  });
}

function createBridge(cfg, { clientFactory = () => new Client() } = {}) {
  const conns = new Map();
  const tasks = new Map();

  function getConn(name) {
    if (conns.has(name)) return conns.get(name);
    const p = new Promise((resolve, reject) => {
      const entry = resolveHost(cfg, name);
      const client = clientFactory({});
      let ready = false;
      client.on('ready', () => { ready = true; resolve(client); });
      client.on('error', (err) => reject(new Error(`SSH connection to ${entry.name} failed: ${err.message}`)));
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
    // pty commands are already made session/process-group leaders by the SSH
    // server (setsid + TIOCSCTTY on the pty), so wrapping them in setsid again
    // would fail with EPERM on real OpenSSH. Only non-pty commands with a
    // sudo/cwd wrapper get the setsid + pidFile treatment; pty timeouts keep
    // the original ch.signal('SIGKILL') behavior (top shell only).
    const wrap = !pty && (sudo || cwd);
    const pidFile = wrap ? `/tmp/ssh-bridge-pid-${crypto.randomBytes(6).toString('hex')}` : null;
    let full;
    if (wrap) {
      // setsid detaches the command into its own session, making it the
      // session leader whose PID equals the process-group id. The child pid is
      // captured to a file so a timeout can signal the whole tree via
      // kill(-pgid); the EXIT trap removes the pid file on normal completion.
      const inner = makeExecCommand({ command, cwd, sudo });
      const capture = `echo $$ > ${pidFile}; trap 'rm -f ${pidFile}' EXIT;\n`;
      full = `setsid bash -c ${shq(capture + inner)}`;
    } else {
      // Non-wrapped path (plain or pty): apply cwd/sudo exactly as before the
      // setsid change, and let pty timeouts use ch.signal('SIGKILL').
      full = makeExecCommand({ command, cwd, sudo });
    }
    const opts = {};
    if (pty) opts.pty = { rows: 40, cols: 200, term: 'xterm-256color' };
    if (env) opts.env = env;
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
          finish(null);
        });
        ch.on('ready', () => {
          if (sudo && sudoPassword) ch.stdin.write(sudoPassword + '\n');
          if (input) ch.stdin.write(input);
          ch.stdin.end();
        });
        ch.on('exit', (code) => { exitCode = code; });
        ch.on('data', (d) => { stdout = append(stdout, d.toString(), () => { stdoutTruncated = true; }); });
        ch.stderr.on('data', (d) => { stderr = append(stderr, d.toString(), () => { stderrTruncated = true; }); });
        ch.on('close', (code) => {
          if (done) return;
          done = true;
          clearTimeout(timer);
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
    return getConn(entry.name).then((client) =>
      execChannel(client, { ...args, sudoPassword: entry.sudoPassword })
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

  async function readFile(name, file) {
    const s = await getSftp(name);
    return new Promise((resolve, reject) =>
      s.readFile(file, 'utf8', (e, d) =>
        e ? reject(new Error(`read_file ${file}: ${e.message}`)) : resolve({ content: d })
      )
    );
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

  async function writeFile(name, file, content) {
    const s = await getSftp(name);
    await writeRemoteFile(s, file, content);
    return { ok: true };
  }

  async function upload(name, localPath, remotePath) {
    const s = await getSftp(name);
    await mkdirp(s, path.posix.dirname(remotePath));
    await new Promise((resolve, reject) =>
      s.fastPut(localPath, remotePath, (e) =>
        e ? reject(new Error(`upload: ${e.message}`)) : resolve()
      )
    );
    return { ok: true };
  }

  async function download(name, remotePath, localPath) {
    const s = await getSftp(name);
    fs.mkdirSync(path.dirname(localPath), { recursive: true });
    await new Promise((resolve, reject) =>
      s.fastGet(remotePath, localPath, (e) =>
        e ? reject(new Error(`download: ${e.message}`)) : resolve()
      )
    );
    return { ok: true };
  }

  async function startBackground(name, { command, cwd }) {
    const entry = resolveHost(cfg, name);
    const taskId = crypto.randomBytes(6).toString('hex');
    const scriptFile = `/tmp/ssh-bridge-${taskId}.sh`;
    const outFile = `/tmp/ssh-bridge-${taskId}.out`;
    const pidFile = `/tmp/ssh-bridge-${taskId}.pid`;
    const s = await getSftp(entry.name);
    await writeRemoteFile(s, scriptFile, command);
    const run = `cd ${shq(cwd || '.')} && nohup bash ${shq(scriptFile)} > ${outFile} 2>&1 & echo $! > ${pidFile}`;
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
  }

  async function backgroundLogs(taskId) {
    const t = tasks.get(taskId);
    if (!t) throw new Error(`unknown task_id ${taskId}`);
    const s = await getSftp(t.hostName);
    const { content, size } = await readFrom(s, t.outFile, t.offset);
    t.offset = size;
    const alive = await runCommand(t.hostName, { command: `kill -0 ${t.pid} 2>/dev/null || true`, timeoutMs: 5000 });
    return { content, running: alive.exitCode === 0 };
  }

  function readFrom(sftp, file, offset) {
    return new Promise((resolve) => {
      sftp.open(file, 'r', (e, h) => {
        if (e) return resolve({ content: '', size: offset });
        sftp.fstat(h, (e2, st) => {
          if (e2) return resolve({ content: '', size: offset });
          // If the file shrank (rotated/truncated) below our offset, restart
          // from the beginning instead of permanently skipping the new data.
          const start = st.size < offset ? 0 : offset;
          const n = st.size - start;
          if (n <= 0) return resolve({ content: '', size: st.size });
          const buf = Buffer.alloc(n);
          sftp.read(h, buf, 0, n, start, (e3, bytes) => {
            resolve({ content: buf.subarray(0, bytes).toString('utf8'), size: st.size });
          });
        });
      });
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

module.exports = { createBridge, makeExecCommand, stripAnsi, mkdirp, killProcessGroup, MAX_OUTPUT };
