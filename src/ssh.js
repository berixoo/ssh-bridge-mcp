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

function createBridge(cfg, { clientFactory = () => new Client() } = {}) {
  const conns = new Map();
  const tasks = new Map();

  function getConn(name) {
    if (conns.has(name)) return conns.get(name);
    const p = new Promise((resolve, reject) => {
      const entry = resolveHost(cfg, name);
      const client = clientFactory({});
      client.on('ready', () => resolve(client));
      client.on('error', (err) => reject(new Error(`SSH connection to ${entry.name} failed: ${err.message}`)));
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
    const full = makeExecCommand({ command, cwd, sudo });
    const opts = {};
    if (pty) opts.pty = { rows: 40, cols: 200, term: 'xterm-256color' };
    if (env) opts.env = env;
    const timeout = timeoutMs || 30000;
    return new Promise((resolve, reject) => {
      client.exec(full, opts, (err, ch) => {
        if (err) return reject(new Error(`exec failed: ${err.message}`));
        let stdout = '';
        let stderr = '';
        let exitCode = null;
        let timedOut = false;
        let done = false;
        const timer = setTimeout(() => {
          timedOut = true;
          ch.signal('SIGKILL');
          finish();
        }, timeout);
        const finish = () => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          let out = stdout;
          let errOut = stderr;
          if (pty) {
            out = stripAnsi(out.replace(/\r/g, ''));
            errOut = stripAnsi(errOut.replace(/\r/g, ''));
          }
          const cOut = cap(out);
          const cErr = cap(errOut);
          resolve({
            exitCode,
            stdout: cOut.text,
            stderr: cErr.text,
            timedOut,
            truncated: cOut.truncated || cErr.truncated,
          });
        };
        ch.on('ready', () => {
          if (sudo && sudoPassword) ch.stdin.write(sudoPassword + '\n');
          if (input) ch.stdin.write(input);
          ch.stdin.end();
        });
        ch.on('exit', (code) => { exitCode = code; });
        ch.on('data', (d) => { stdout += d.toString(); });
        ch.stderr.on('data', (d) => { stderr += d.toString(); });
        ch.on('close', (code) => {
          if (exitCode === null) exitCode = code;
          finish();
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
    await new Promise((resolve, reject) =>
      sftp.mkdir(dir, { recursive: true }, (e) => (e ? reject(e) : resolve()))
    );
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
    await new Promise((resolve, reject) =>
      s.mkdir(path.posix.dirname(remotePath), { recursive: true }, (e) => (e ? reject(e) : resolve()))
    );
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
    if (r.exitCode !== 0) throw new Error(`start_background failed: ${r.stderr}`);
    const pidR = await runCommand(entry.name, { command: `cat ${pidFile}`, timeoutMs: 5000 });
    const pid = pidR.stdout.trim();
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
          const n = st.size - offset;
          if (n <= 0) return resolve({ content: '', size: st.size });
          const buf = Buffer.alloc(n);
          sftp.read(h, buf, 0, n, offset, (e3, bytes) => {
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

module.exports = { createBridge, makeExecCommand, stripAnsi };
