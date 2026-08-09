# SSH Bridge MCP 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 一个本机运行、把 SSH 封装成结构化工具的 MCP server，让 Claude Code / Codex / Claude Desktop 通过 9 个工具操作多台局域网 Linux（跑命令、读写文件、传输、后台进程）。

**Architecture:** 单进程 Node MCP server（官方 `@modelcontextprotocol/sdk`），配置在本地 `config.json`。每个 host 一个懒加载可复用 ssh2 连接（失败自动重建）。命令走 exec（多行即 shell 脚本），文件走 SFTP，后台进程用「脚本文件 + nohup + PID 文件 + 日志文件」实现，避免长驻 channel。测试用脚本化 mock ssh2 Client 注入，node:test + assert，零测试框架。

**Tech Stack:** Node.js、`@modelcontextprotocol/sdk`（^1.12.1）、`ssh2`、`zod`（^3.24.4）、node:test。

## Global Constraints

- 纯 JS，无构建步骤（`npm start` = `node src/server.js`）。
- 依赖版本对齐：`@modelcontextprotocol/sdk ^1.12.1`、`zod ^3.24.4`（与 `../mcp-mimo-search` 一致）。
- 代码、注释、字符串、README 中**不得出现任何 emoji**。
- 文件默认 UTF-8 无 BOM。
- 远程路径是 POSIX 路径（用 `path.posix`），本地路径是 Windows 路径。
- 凭据（password / sudoPassword）**绝不出现在工具输出**、日志或错误信息里。`list_hosts` 只返回 host/port/user。
- 后台进程：`task_id → { hostName, pid, scriptFile, outFile, pidFile, offset }`。
- 测试命令：`node --test tests/`。冒烟：`node scripts/smoke.mjs`。

---

### Task 1: 项目脚手架

**Files:**
- Create: `package.json`
- Create: `.gitignore`
- Create: `config.example.json`

**Interfaces:**
- Produces: `package.json` 声明 `start`/`test` scripts；`.gitignore` 排除 `config.json` 与 `node_modules`。

- [ ] **Step 1: 创建 package.json**

```json
{
  "name": "ssh-bridge-mcp",
  "version": "1.0.0",
  "description": "MCP server bridging SSH to LAN Linux hosts for coding agents",
  "main": "src/server.js",
  "bin": { "ssh-bridge-mcp": "src/server.js" },
  "scripts": {
    "start": "node src/server.js",
    "test": "node --test tests/"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.12.1",
    "ssh2": "^1.16.0",
    "zod": "^3.24.4"
  }
}
```

- [ ] **Step 2: 创建 .gitignore**

```
node_modules/
config.json
```

（`config.json` 含真实密码，永远不入 git。仓库只提交 `config.example.json`。）

- [ ] **Step 3: 创建 config.example.json**

```json
{
  "default": "dev01",
  "hosts": {
    "dev01": {
      "host": "192.168.1.10",
      "port": 22,
      "user": "roooi",
      "password": "your-ssh-password",
      "sudoPassword": "your-sudo-password"
    }
  }
}
```

- [ ] **Step 4: 安装依赖并验证**

Run: `cd C:/workspace/MCP/ssh-bridge-mcp && npm install`
Expected: 安装成功。再跑 `node -e "require('ssh2'); require('@modelcontextprotocol/sdk/server/mcp.js'); console.log('ok')"`，输出 `ok`。

- [ ] **Step 5: Commit**

```bash
git add package.json package-lock.json .gitignore config.example.json
git commit -m "chore: scaffold ssh-bridge-mcp project"
```

---

### Task 2: 配置加载模块

**Files:**
- Create: `src/config.js`
- Create: `tests/config.test.js`

**Interfaces:**
- Consumes: `zod`。
- Produces:
  - `loadConfig()` → `{ default?, hosts }`（校验后的配置对象）
  - `resolveHost(cfg, name?)` → `{ name, host, port, user, password?, sudoPassword? }`
    - `name` 缺省时依次取 `cfg.default` → 第一个 host。
    - `sudoPassword` 缺省回落到 `password`。

- [ ] **Step 1: 写失败的测试**

Create `tests/config.test.js`：

```js
const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveHost } = require('../src/config');

test('resolveHost uses default when name omitted', () => {
  const cfg = { default: 'b', hosts: { a: { host: '1', user: 'u' }, b: { host: '2', user: 'u' } } };
  assert.equal(resolveHost(cfg).name, 'b');
});

test('resolveHost falls back to first host without default', () => {
  const cfg = { hosts: { a: { host: '1', user: 'u' } } };
  assert.equal(resolveHost(cfg).name, 'a');
});

test('resolveHost throws on unknown host', () => {
  const cfg = { hosts: { a: { host: '1', user: 'u' } } };
  assert.throws(() => resolveHost(cfg, 'nope'), /unknown host/);
});

test('sudoPassword falls back to password', () => {
  const cfg = { hosts: { a: { host: '1', user: 'u', password: 'p' } } };
  assert.equal(resolveHost(cfg, 'a').sudoPassword, 'p');
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `node --test tests/config.test.js`
Expected: FAIL，`Cannot find module '../src/config'`。

- [ ] **Step 3: 写实现**

Create `src/config.js`：

```js
const fs = require('fs');
const path = require('path');
const { z } = require('zod');

const HostSchema = z.object({
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535).default(22),
  user: z.string().min(1),
  password: z.string().optional(),
  sudoPassword: z.string().optional(),
});

const ConfigSchema = z
  .object({
    default: z.string().optional(),
    hosts: z.record(z.string(), HostSchema),
  })
  .refine((c) => Object.keys(c.hosts).length > 0, { message: 'at least one host required' });

function configPath() {
  return process.env.SSH_BRIDGE_CONFIG || path.join(__dirname, '..', 'config.json');
}

function loadConfig() {
  const file = configPath();
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (e) {
    throw new Error(`config not found at ${file} (set SSH_BRIDGE_CONFIG to override)`);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    throw new Error(`config ${file} is not valid JSON: ${e.message}`);
  }
  const cfg = ConfigSchema.parse(parsed);
  if (cfg.default && !cfg.hosts[cfg.default]) {
    throw new Error(`default host "${cfg.default}" not defined in hosts`);
  }
  return cfg;
}

function resolveHost(cfg, name) {
  const key = name || cfg.default || Object.keys(cfg.hosts)[0];
  const entry = cfg.hosts[key];
  if (!entry) throw new Error(`unknown host "${name}"`);
  return { name: key, ...entry, sudoPassword: entry.sudoPassword ?? entry.password };
}

module.exports = { loadConfig, resolveHost, configPath };
```

- [ ] **Step 4: 运行测试验证通过**

Run: `node --test tests/config.test.js`
Expected: PASS（4 个测试）。

- [ ] **Step 5: Commit**

```bash
git add src/config.js tests/config.test.js
git commit -m "feat: config loading and host resolution"
```

---

### Task 3: Mock ssh2 Client（测试脚手架）

**Files:**
- Create: `src/mock-ssh.js`

**Interfaces:**
- Consumes: `node:events`。
- Produces:
  - `createMockClientFactory({ onExec, onSftp })` → `factory(connConfig)` 返回一个 ssh2-Client 兼容的 mock 对象：
    - `client.exec(command, opts, cb)`：`onExec(command, opts)` 返回 `{ code, stdout, stderr, onWrite }`，构造一个 mock channel（emit `ready` → data → `close`），收集 `ch.stdin.write` 内容。
    - `client.sftp(cb)`：`onSftp()` 返回 mock SFTP。
    - mock SFTP 提供 `mkdir` / `writeFile` / `readFile` / `fastPut` / `fastGet` / `open` / `fstat` / `read`，内部用 `Map<path, Buffer>` 存文件。
  - 测试通过 `client.calls` 数组断言 exec/sftp 被如何调用。

- [ ] **Step 1: 写实现**

Create `src/mock-ssh.js`：

```js
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
```

- [ ] **Step 2: 验证 mock 可被 require**

Run: `node -e "const m = require('./src/mock-ssh'); m.createMockClientFactory(); console.log('ok')"`
Expected: 输出 `ok`。

- [ ] **Step 3: Commit**

```bash
git add src/mock-ssh.js
git commit -m "test: mock ssh2 client scaffold"
```

---

### Task 4: SSH 连接与执行层

**Files:**
- Create: `src/ssh.js`
- Create: `tests/ssh.test.js`

**Interfaces:**
- Consumes: `ssh2`、`resolveHost`、`createMockClientFactory`。
- Produces（`createBridge(cfg, { clientFactory })` 返回的对象）：
  - `listHosts()` → `[{ name, host, port, user }]`（**不含凭据**）
  - `runCommand(hostName, { command, cwd, timeoutMs, sudo, pty, env, input })` → `{ exitCode, stdout, stderr, timedOut, truncated }`
  - `readFile(hostName, path)` → `{ content }`
  - `writeFile(hostName, path, content)` → `{ ok: true }`
  - `upload(hostName, localPath, remotePath)` → `{ ok: true }`
  - `download(hostName, remotePath, localPath)` → `{ ok: true }`
  - `startBackground(hostName, { command, cwd })` → `{ taskId, pid }`
  - `backgroundLogs(taskId)` → `{ content, running }`（增量，内部维护 offset）
  - `stopBackground(taskId)` → `{ ok: true }`
  - 内部：`getConn(name)` 每个 host 懒建一个连接，失败 evict 后重试；`task_id` 用 `crypto.randomBytes(6).toString('hex')`。

**Global constants:** `MAX_OUTPUT = 500 * 1024`，`ANSI_RE = /\x1b\[[0-9;?]*[A-Za-z]/g`。

- [ ] **Step 1: 写失败的测试**

Create `tests/ssh.test.js`：

```js
const test = require('node:test');
const assert = require('node:assert/strict');
const { createBridge } = require('../src/ssh');
const { createMockClientFactory, makeSftp } = require('../src/mock-ssh');

const cfg = {
  default: 'dev',
  hosts: { dev: { host: '10.0.0.1', port: 22, user: 'u', password: 'pw', sudoPassword: 'sw' } },
};

function makeBridge(handlers) {
  return createBridge(cfg, { clientFactory: createMockClientFactory(handlers) });
}

test('listHosts exposes address but not credentials', () => {
  const b = makeBridge();
  assert.deepEqual(b.listHosts(), [{ name: 'dev', host: '10.0.0.1', port: 22, user: 'u' }]);
});

test('runCommand returns exit code, stdout, stderr', async () => {
  const b = makeBridge({ onExec: (cmd) => ({ code: 1, stdout: 'out', stderr: 'err' }) });
  const r = await b.runCommand('dev', { command: 'echo hi' });
  assert.deepEqual(r, { exitCode: 1, stdout: 'out', stderr: 'err', timedOut: false, truncated: false });
});

test('runCommand prefixes cwd and wraps sudo with sh -c', async () => {
  let seen;
  const b = makeBridge({ onExec: (cmd) => { seen = cmd; return { code: 0 }; } });
  await b.runCommand('dev', { command: "apt install 'pkg'", cwd: '/app', sudo: true });
  assert.equal(seen, "cd '/app' && sudo -S -p '' sh -c 'apt install '\\''pkg'\\'''");
});

test('runCommand passes env option to exec', async () => {
  let seenOpts;
  const b = makeBridge({ onExec: (_c, opts) => { seenOpts = opts; return { code: 0 }; } });
  await b.runCommand('dev', { command: 'npm test', env: { NODE_ENV: 'test' } });
  assert.deepEqual(seenOpts.env, { NODE_ENV: 'test' });
});

test('runCommand writes sudo password then input then ends stdin', async () => {
  let writes = [];
  const b = makeBridge({ onExec: (cmd) => ({ code: 0, onWrite: (w) => writes.push(w) }) });
  await b.runCommand('dev', { command: 'cat', sudo: true, input: 'hello' });
  assert.deepEqual(writes, ['sw\n', 'hello']);
});

test('runCommand reports timeout', async () => {
  const b = makeBridge({ onExec: () => ({ _neverClose: true }) });
  const start = Date.now();
  const r = await b.runCommand('dev', { command: 'sleep', timeoutMs: 50 });
  assert.equal(r.timedOut, true);
  assert.ok(Date.now() - start < 3000);
});

test('readFile returns content', async () => {
  const sftp = makeSftp();
  sftp._files.set('/a.txt', Buffer.from('hi'));
  const b = makeBridge({ onSftp: () => sftp });
  const r = await b.readFile('dev', '/a.txt');
  assert.equal(r.content, 'hi');
});

test('writeFile mkdirs parent then writes', async () => {
  const sftp = makeSftp();
  const b = makeBridge({ onSftp: () => sftp });
  await b.writeFile('dev', '/deep/dir/f.txt', 'content');
  assert.equal(sftp._files.get('/deep/dir/f.txt').toString(), 'content');
});

test('upload calls fastPut after mkdir', async () => {
  const sftp = makeSftp();
  let mkdirs = [];
  sftp.mkdir = (p, opts, cb) => { mkdirs.push(p); cb(null); };
  const b = makeBridge({ onSftp: () => sftp });
  await b.upload('dev', 'C:\\tmp\\x.txt', '/r/d/x.txt');
  assert.deepEqual(mkdirs, ['/r/d']);
  assert.ok(sftp._files.has('/r/d/x.txt'));
});

test('startBackground then backgroundLogs then stopBackground', async () => {
  const sftp = makeSftp();
  const execLog = [];
  const b = makeBridge({
    onSftp: () => sftp,
    onExec: (cmd) => {
      execLog.push(cmd);
      if (cmd.includes('kill -0')) return { code: 1 }; // 进程已死（kill 失败）
      if (cmd.includes('kill -9')) return { code: 0 };
      if (cmd.startsWith('cat ')) return { code: 0, stdout: '12345\n' };
      return { code: 0, stdout: '12345\n' };
    },
  });
  const { taskId } = await b.startBackground('dev', { command: 'npm run dev', cwd: '/app' });
  assert.ok(taskId);
  assert.ok(execLog.some((c) => c.includes('nohup bash')));
  sftp._files.set(`/tmp/ssh-bridge-${taskId}.out`, Buffer.from('line1\nline2\n'));
  const logs1 = await b.backgroundLogs(taskId);
  assert.equal(logs1.content, 'line1\nline2\n');
  assert.equal(logs1.running, false);
  const logs2 = await b.backgroundLogs(taskId);
  assert.equal(logs2.content, '');
  const stop = await b.stopBackground(taskId);
  assert.deepEqual(stop, { ok: true });
});
```

- [ ] **Step 2: 运行测试验证失败**

Run: `node --test tests/ssh.test.js`
Expected: FAIL，`Cannot find module '../src/ssh'`。

- [ ] **Step 3: 写实现**

Create `src/ssh.js`：

```js
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
```

- [ ] **Step 4: 修复测试里的超时用例**

mock `makeChannel` 目前固定会 emit `close`，无法表达「永不返回」的场景。给 `makeChannel` 加一个 `_neverClose` 支持：

Modify `src/mock-ssh.js` 的 `makeChannel` 尾部：

```js
  setImmediate(() => {
    ch.emit('ready');
    if (stdout) ch.emit('data', Buffer.from(stdout));
    if (stderr) ch.stderr.emit('data', Buffer.from(stderr));
    if (!res._neverClose) ch.emit('close', code);
  });
```

然后简化测试里的 timeout 用例：

```js
test('runCommand reports timeout', async () => {
  const b = makeBridge({ onExec: () => ({ _neverClose: true }) });
  const start = Date.now();
  const r = await b.runCommand('dev', { command: 'sleep', timeoutMs: 50 });
  assert.equal(r.timedOut, true);
  assert.ok(Date.now() - start < 3000);
});
```

- [ ] **Step 5: 运行全部测试**

Run: `node --test tests/`
Expected: PASS（config 4 个 + ssh 9 个）。若 timeout 用例偶发不稳定（`signal` 后 mock 仍在跑），允许保留 3 秒松弛断言。

- [ ] **Step 6: Commit**

```bash
git add src/ssh.js src/mock-ssh.js tests/ssh.test.js
git commit -m "feat: ssh connection pool, command exec, sftp, background processes"
```

---

### Task 5: MCP server 集成

**Files:**
- Create: `src/server.js`
- Create: `tests/fixtures/config.test.json`
- Create: `scripts/smoke.mjs`

**Interfaces:**
- Consumes: `createBridge`、`loadConfig`、`@modelcontextprotocol/sdk/server/mcp.js`、`@modelcontextprotocol/sdk/server/stdio.js`、`zod`。
- Produces: 9 个 MCP 工具（`list_hosts` / `run_command` / `read_file` / `write_file` / `upload` / `download` / `start_background` / `background_logs` / `stop_background`）。每个 handler 返回 `{ content: [{ type: 'text', text: JSON.stringify(result) }] }`。未捕获错误 → 抛 Error（SDK 转成 MCP 错误响应）。

- [ ] **Step 1: 写失败的冒烟测试**

Create `tests/fixtures/config.test.json`：

```json
{
  "default": "dev",
  "hosts": {
    "dev": { "host": "127.0.0.1", "port": 22, "user": "x", "password": "p" }
  }
}
```

Create `scripts/smoke.mjs`：

```js
import { spawn } from 'node:child_process';

const child = spawn('node', ['src/server.js'], {
  cwd: process.cwd(),
  env: { ...process.env, SSH_BRIDGE_CONFIG: 'tests/fixtures/config.test.json' },
  stdio: ['pipe', 'pipe', 'inherit'],
});
let buf = '';
let pending = new Map();
let nextId = 1;
let done = false;

child.stdout.on('data', (d) => {
  buf += d.toString();
  let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    if (!line.trim()) continue;
    const msg = JSON.parse(line);
    if (msg.id && pending.has(msg.id)) pending.get(msg.id)(msg);
  }
});

function call(method, params = {}) {
  const id = nextId++;
  return new Promise((resolve) => {
    pending.set(id, resolve);
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
}

await call('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'smoke', version: '0' } });
await call('notifications/initialized');
const list = await call('tools/list', {});
const names = list.result.tools.map((t) => t.name).sort();
const expected = ['list_hosts', 'run_command', 'read_file', 'write_file', 'upload', 'download', 'start_background', 'background_logs', 'stop_background'].sort();
if (JSON.stringify(names) !== JSON.stringify(expected)) {
  console.error('SMOKE FAIL: tools mismatch');
  console.error('got:', names);
  process.exit(1);
}
console.log('SMOKE OK: 9 tools registered');
child.kill();
process.exit(0);
```

- [ ] **Step 2: 运行冒烟验证失败**

Run: `node scripts/smoke.mjs`
Expected: FAIL，`Cannot find module '../src/server.js'`（子进程 stderr 报错，冒烟卡在等待响应后退出码非 0 或超时）。

- [ ] **Step 3: 写实现**

Create `src/server.js`：

```js
#!/usr/bin/env node
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { z } = require('zod');
const { createBridge } = require('./ssh');
const { loadConfig } = require('./config');

const cfg = loadConfig();
const bridge = createBridge(cfg);

const server = new McpServer({ name: 'ssh-bridge-mcp', version: '1.0.0' });

const hostSchema = z.string().optional().describe('host name from config; defaults to configured default host');
const ok = (data) => ({ content: [{ type: 'text', text: JSON.stringify(data) }] });
const toolError = (e) => new Error(e.message || String(e));

server.registerTool('list_hosts', {
  description: 'List available SSH hosts (name, host, port, user). No credentials are shown.',
  inputSchema: {},
}, async () => ok(bridge.listHosts()));

server.registerTool('run_command', {
  description: 'Run a shell command on a remote host. command is a shell string (multi-line supported, runs via the remote shell). env injects environment variables. sudo runs the command as root (password handled by server). pty allocates a terminal (for CLIs that need a tty). input writes one-shot text to stdin. Returns { exitCode, stdout, stderr, timedOut, truncated }. Non-zero exit is NOT an error.',
  inputSchema: {
    host: hostSchema,
    command: z.string().min(1),
    cwd: z.string().optional().describe('working directory; cd before command'),
    timeoutMs: z.number().int().min(1).max(600000).optional().describe('default 30000'),
    sudo: z.boolean().optional().default(false),
    pty: z.boolean().optional().default(false),
    env: z.record(z.string(), z.string()).optional(),
    input: z.string().optional().describe('one-shot stdin, written then closed'),
  },
}, async (args) => {
  try {
    return ok(await bridge.runCommand(args.host, args));
  } catch (e) { throw toolError(e); }
});

server.registerTool('read_file', {
  description: 'Read a text file on the remote host (small files only; use download for large).',
  inputSchema: { host: hostSchema, path: z.string().min(1) },
}, async (args) => {
  try { return ok(await bridge.readFile(args.host, args.path)); } catch (e) { throw toolError(e); }
});

server.registerTool('write_file', {
  description: 'Write text content to a remote file, creating parent directories.',
  inputSchema: { host: hostSchema, path: z.string().min(1), content: z.string() },
}, async (args) => {
  try { return ok(await bridge.writeFile(args.host, args.path, args.content)); } catch (e) { throw toolError(e); }
});

server.registerTool('upload', {
  description: 'Upload a local (Windows) file to a remote POSIX path via SFTP. Creates remote directories.',
  inputSchema: { host: hostSchema, local_path: z.string().min(1), remote_path: z.string().min(1) },
}, async (args) => {
  try { return ok(await bridge.upload(args.host, args.local_path, args.remote_path)); } catch (e) { throw toolError(e); }
});

server.registerTool('download', {
  description: 'Download a remote file to a local (Windows) path via SFTP.',
  inputSchema: { host: hostSchema, remote_path: z.string().min(1), local_path: z.string().min(1) },
}, async (args) => {
  try { return ok(await bridge.download(args.host, args.remote_path, args.local_path)); } catch (e) { throw toolError(e); }
});

server.registerTool('start_background', {
  description: 'Start a long-running process (dev server, training) on a remote host. Returns a task_id to poll logs or stop it.',
  inputSchema: {
    host: hostSchema,
    command: z.string().min(1),
    cwd: z.string().optional(),
  },
}, async (args) => {
  try { return ok(await bridge.startBackground(args.host, args)); } catch (e) { throw toolError(e); }
});

server.registerTool('background_logs', {
  description: 'Read new log output since the last call for a background task. Returns { content, running }.',
  inputSchema: { task_id: z.string().min(1) },
}, async (args) => {
  try { return ok(await bridge.backgroundLogs(args.task_id)); } catch (e) { throw toolError(e); }
});

server.registerTool('stop_background', {
  description: 'Kill a background task started with start_background.',
  inputSchema: { task_id: z.string().min(1) },
}, async (args) => {
  try { return ok(await bridge.stopBackground(args.task_id)); } catch (e) { throw toolError(e); }
});

const transport = new StdioServerTransport();
server.connect(transport).catch((e) => {
  console.error(`[ssh-bridge-mcp] fatal: ${e.message}`);
  process.exit(1);
});
```

- [ ] **Step 4: 运行冒烟验证通过**

Run: `node scripts/smoke.mjs`
Expected: 输出 `SMOKE OK: 9 tools registered`，退出码 0。

- [ ] **Step 5: Commit**

```bash
git add src/server.js tests/fixtures/config.test.json scripts/smoke.mjs
git commit -m "feat: MCP server with 9 tools"
```

---

### Task 6: README

**Files:**
- Create: `README.md`

**Interfaces:**
- Produces: 文档，含配置模板、Claude Desktop / Claude Code 接入方法、9 个工具一览、面向 agent 的使用说明（直接采用 spec 的「使用说明」章节内容）。

- [ ] **Step 1: 写 README.md**

内容要点（照 spec 扩充，无 emoji，UTF-8）：

```markdown
# ssh-bridge-mcp

让 Claude Code / Codex / Claude Desktop 通过 MCP 统一操作局域网 Linux 的 SSH 桥。

## 快速开始

1. `npm install`
2. 复制 `config.example.json` 为 `config.json` 并填写主机与密码（sudoPassword 缺省同 password）
3. 启动：`npm start`（或用 `SSH_BRIDGE_CONFIG=/path/to/config.json npm start` 指定配置）

## 接入

### Claude Desktop

在 `claude_desktop_config.json` 增加：

```json
{
  "mcpServers": {
    "ssh-bridge": {
      "command": "node",
      "args": ["C:/workspace/MCP/ssh-bridge-mcp/src/server.js"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add ssh-bridge -- node C:/workspace/MCP/ssh-bridge-mcp/src/server.js
```

## 工具

| 工具 | 作用 |
|---|---|
| list_hosts | 列出主机（不含凭据） |
| run_command | 跑 shell 命令（多行/sudo/pty/env/input） |
| read_file / write_file | 读/写远程文本（小文件） |
| upload / download | SFTP 传文件（大文件/目录） |
| start_background / background_logs / stop_background | 后台长驻进程 |

## 使用说明（给 agent）

...（照 spec「使用说明」章节，含 env / 多行 / sudo / 超时 / 文件 / 后台 / 组合示例）
```

具体正文直接引用 spec 的 7 条约定与示例，写成 Markdown。

- [ ] **Step 2: 校验 README 无 emoji、格式正常**

Run: `node -e "const s=require('fs').readFileSync('README.md','utf8'); if(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u.test(s)){console.error('emoji found');process.exit(1)} console.log('README OK')"`
Expected: `README OK`。

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: README with config, setup, and agent usage guide"
```

---

### Task 7: 终验

**Files:**
- 无新增。

- [ ] **Step 1: 跑全量测试**

Run: `node --test tests/`
Expected: 全部 PASS。

- [ ] **Step 2: 跑冒烟**

Run: `node scripts/smoke.mjs`
Expected: `SMOKE OK: 9 tools registered`，退出码 0。

- [ ] **Step 3: 真实连接自检（若手头有可连的 Linux）**

Run: 将 `config.json` 指向真实主机，`node scripts/smoke.mjs` 之外手动跑：
`echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_command","arguments":{"command":"echo hello"}}}' | node src/server.js`
Expected: 返回 `{"exitCode":0,"stdout":"hello\n",...}`。无环境则跳过，并在交付说明里注明「真实连接需用户自行验证」。

- [ ] **Step 4: 最终提交（若无未提交变更则跳过）**

```bash
git status --porcelain
git add -A && git commit -m "chore: final verification"
```
