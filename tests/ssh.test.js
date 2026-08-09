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
