const test = require('node:test');
const assert = require('node:assert/strict');
const { createBridge, makeExecCommand, MAX_OUTPUT } = require('../src/ssh');
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

test('runCommand wraps with setsid, captures pid, and applies sudo/cwd payload', async () => {
  let seen;
  const b = makeBridge({ onExec: (cmd) => { seen = cmd; return { code: 0 }; } });
  await b.runCommand('dev', { command: "apt install 'pkg'", cwd: '/app', sudo: true });
  assert.ok(seen.startsWith('setsid bash -c '), `expected setsid wrapper, got: ${seen}`);
  const pidM = seen.match(/\/tmp\/ssh-bridge-pid-([a-f0-9]+);/);
  assert.ok(pidM, 'expected pid capture');
  // Rebuild the expected command from the same pieces as the implementation
  // and compare after normalizing the random pid.
  const inner = makeExecCommand({ command: "apt install 'pkg'", cwd: '/app', sudo: true });
  const shq = (s) => "'" + s.replace(/'/g, `'\\''`) + "'";
  const expected = `setsid bash -c ${shq(`echo $$ > /tmp/ssh-bridge-pid-<PID>;\n${inner}`)}`.replace('<PID>', pidM[1]);
  assert.equal(seen, expected);
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

test('runCommand rejects when connection drops mid-command and pool rebuilds', async () => {
  const factory = createMockClientFactory({ onExec: () => ({ _drop: true }) });
  const b = createBridge(cfg, { clientFactory: factory });
  await assert.rejects(b.runCommand('dev', { command: 'sleep' }), /connection closed before command completed/);
  // Let the mock's client-close flush so the pool evicts the dead connection.
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(factory._clients.length, 1);
  await assert.rejects(b.runCommand('dev', { command: 'sleep' }), /connection closed before command completed/);
  assert.equal(factory._clients.length, 2, 'pool must rebuild a fresh connection');
});

test('runCommand kills the process group on timeout', async () => {
  const kills = [];
  const b = makeBridge({
    onExec: (cmd) => {
      if (cmd.startsWith('kill -TERM -- -')) { kills.push(cmd); return { code: 0 }; }
      return { _neverClose: true };
    },
  });
  const r = await b.runCommand('dev', { command: 'sleep', timeoutMs: 50, cwd: '/app' });
  assert.equal(r.timedOut, true);
  assert.ok(
    kills.some((k) => /kill -TERM -- -\$\(cat \/tmp\/ssh-bridge-pid-[a-f0-9]+\)/.test(k)),
    `expected a process-group kill, got: ${kills.join(' | ')}`
  );
});

test('runCommand caps accumulated output at MAX_OUTPUT', async () => {
  const chunk = 'x'.repeat(51200);
  const chunks = new Array(20).fill(chunk); // 1MB total
  const b = makeBridge({ onExec: () => ({ code: 0, stdout: chunks }) });
  const r = await b.runCommand('dev', { command: 'yes' });
  assert.equal(r.stdout.length, MAX_OUTPUT);
  assert.equal(r.truncated, true);
  assert.equal(r.exitCode, 0);
});

test('backgroundLogs resets offset when the log file is truncated', async () => {
  const sftp = makeSftp();
  const b = makeBridge({
    onSftp: () => sftp,
    onExec: (cmd) => {
      if (cmd.includes('kill -0')) return { code: 1 }; // 进程已死（kill 失败）
      if (cmd.startsWith('cat ')) return { code: 0, stdout: '12345\n' };
      return { code: 0, stdout: '12345\n' };
    },
  });
  const { taskId } = await b.startBackground('dev', { command: 'echo hi', cwd: '/app' });
  const outFile = `/tmp/ssh-bridge-${taskId}.out`;
  sftp._files.set(outFile, Buffer.from('abcdef'));
  const first = await b.backgroundLogs(taskId);
  assert.equal(first.content, 'abcdef');
  // Simulate rotation: the file shrinks below the stored offset.
  sftp._files.set(outFile, Buffer.from('xyz'));
  const second = await b.backgroundLogs(taskId);
  assert.equal(second.content, 'xyz', 'offset must reset when the file shrank');
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
  sftp.mkdir = (p, opts, cb) => {
    if (typeof opts === 'function') { cb = opts; opts = {}; }
    mkdirs.push(p);
    const parent = require('path').posix.dirname(p);
    if (!sftp._files.has(parent)) { const e = new Error('ENOENT'); e.code = 2; return cb(e); }
    sftp._files.set(p, null);
    cb(null);
  };
  const b = makeBridge({ onSftp: () => sftp });
  await b.upload('dev', 'C:\\tmp\\x.txt', '/r/d/x.txt');
  assert.deepEqual(mkdirs, ['/r', '/r/d']);
  assert.ok(sftp._files.has('/r/d/x.txt'));
});

test('writeFile creates missing nested parents', async () => {
  const sftp = makeSftp();
  const b = makeBridge({ onSftp: () => sftp });
  await b.writeFile('dev', '/a/b/c.txt', 'content');
  assert.equal(sftp._files.get('/a/b/c.txt').toString(), 'content');
  assert.equal(sftp._files.get('/a'), null);
  assert.equal(sftp._files.get('/a/b'), null);
});

test('mkdirp skips creation for existing parent dirs', async () => {
  const sftp = makeSftp();
  let mkdirs = [];
  const origMkdir = sftp.mkdir;
  sftp.mkdir = (p, opts, cb) => {
    if (typeof opts === 'function') { cb = opts; opts = {}; }
    mkdirs.push(p);
    origMkdir(p, opts, cb);
  };
  sftp._files.set('/a', null);
  sftp._files.set('/a/b', null);
  const b = makeBridge({ onSftp: () => sftp });
  await b.writeFile('dev', '/a/b/f.txt', 'content');
  assert.deepEqual(mkdirs, []);
  assert.equal(sftp._files.get('/a/b/f.txt').toString(), 'content');
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
