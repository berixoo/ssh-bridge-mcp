#!/usr/bin/env node
'use strict';

// Independent/offline: no bridge/config imports and no network. On Linux this
// also exercises real local sessions. On Windows, --docker adds the same checks
// in an already-installed python:3.12-slim-bookworm image (never pulls images).
const assert = require('assert/strict');
const fs = require('fs/promises');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { createJobManager } = require('../src/jobs');
const { createRuntime } = require('../src/runtime');

const shq = s => `'${String(s).replace(/'/g, `'\\''`)}'`;
let passed = 0;
async function check(name, fn) {
  await fn();
  passed++;
  console.log(`ok ${passed} - ${name}`);
}
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const code = expected => e => e.code === expected;

// Tokenize only the literal shell words emitted by the manager, not commands
// supplied by users. Unlike substring mocks this checks complete quoted args.
function words(s) {
  const out = [];
  let word = '', quote = false, started = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "'") { quote = !quote; started = true; }
    else if (c === '\\' && !quote) { word += s[++i]; started = true; }
    else if (/\s/.test(c) && !quote) {
      if (started) out.push(word);
      word = ''; started = false;
    } else { word += c; started = true; }
  }
  assert.equal(quote, false, 'unbalanced literal quoting');
  if (started) out.push(word);
  return out;
}

function fake() {
  const files = new Map(), jobs = new Map(), calls = [];
  const home = "/home/test ' $literal\n用户/.cache/ssh-bridge/jobs";
  let offline = false, launchFailure = null, opened = 0, closed = 0;
  const missing = () => Object.assign(new Error('missing'), { code: 2 });
  const get = p => { if (!files.has(p)) throw missing(); return files.get(p); };
  const sftp = {
    open(p, _mode, cb) { try { get(p); opened++; cb(null, p); } catch (e) { cb(e); } },
    fstat(p, cb) { cb(null, { size: get(p).length }); },
    read(p, buf, off, length, pos, cb) {
      const data = get(p).subarray(pos, pos + Math.min(length, 2)); // force short packets
      data.copy(buf, off); cb(null, data.length);
    },
    close(_h, cb) { closed++; cb(); },
  };
  const callbacks = {
    shq,
    resolveName: n => { if (!n || n === 'alias' || n === 'host') return 'host'; throw new Error('unknown host'); },
    withSftp: async (_host, fn) => { if (offline) throw new Error('unreachable'); return fn(sftp); },
    writeRemoteFile: async (_s, p, content) => { files.set(p, Buffer.from(content)); },
    readFrom: async (_s, p, offset, limit) => {
      try {
        const b = get(p), data = b.subarray(offset, offset + limit);
        return { content: data.toString(), size: offset + data.length, truncated: b.length > offset + data.length };
      } catch (error) { return { error, size: offset, content: '' }; }
    },
    runCommand: async (host, args) => {
      calls.push({ host, ...args });
      if (offline) throw new Error('unreachable');
      const w = words(args.command);
      assert.deepEqual(w.slice(0, 2), ['bash', '-c']);
      const script = w[2];
      let stdout = '', stderr = '', exitCode = 0;
      if (w[3] === '--') {
        const [action, dir] = w.slice(4), job = jobs.get(dir);
        if (action === 'launch') {
          assert.equal(job, undefined, 'launch must never be replayed');
          jobs.set(dir, { status: 'running', pid: '1234', exitCode: null });
          if (launchFailure) return launchFailure;
        } else if (action === 'stop' && job.status !== 'unknown' && !['succeeded', 'failed', 'stopped'].includes(job.status)) {
          Object.assign(job, { status: 'stopped', exitCode: 143 });
        } else if (action === 'cleanup') {
          assert.notEqual(job.status, 'running');
          for (const p of files.keys()) if (p.startsWith(`${dir}/`)) files.delete(p);
          return { exitCode: 0, stdout: '', stderr: '' };
        }
        const j = jobs.get(dir) || { status: 'unknown', pid: null, exitCode: null };
        stdout = `SSH_BRIDGE_JOB_V1\t${j.status}\t${j.pid || '-'}\t${j.exitCode ?? '-'}\n`;
      } else if (script.includes('SSH_BRIDGE_ROOT_V1')) {
        stdout = `SSH_BRIDGE_ROOT_V1\0${home}\0`;
      } else if (script.includes('command -v')) {
        if (script.includes('/invalid/cwd')) { exitCode = 1; stderr = 'invalid cwd'; }
      } else if (script.includes('metadata.json')) {
        const m = /n >= (\d+) && n <= (\d+)/.exec(script);
        const ids = [...files.keys()].filter(p => p.endsWith('/metadata.json')).map(p => p.split('/').at(-2)).sort();
        stdout = ids.slice(Number(m[1]), Number(m[2]) + 1).join('\n');
      } else { assert.fail(`unexpected command ${script}`); }
      return { exitCode, stdout, stderr, timedOut: false };
    },
  };
  return { callbacks, files, jobs, calls, home, get,
    dir: id => `${home}/${id}`, manager: () => createJobManager(callbacks),
    offline: value => { offline = value; }, launchFailure: value => { launchFailure = value; },
    handles: () => ({ opened, closed }) };
}

async function offlineChecks() {
  await check('invalid cwd never uploads or launches', async () => {
    const f = fake();
    await assert.rejects(f.manager().startBackground('alias', { command: 'touch sentinel', cwd: '/invalid/cwd' }), code('JOB_REMOTE_ERROR'));
    assert.equal(f.files.size, 0); assert.equal(f.jobs.size, 0);
  });
  await check('unsupported and malformed options fail before remote calls', async () => {
    const f = fake(), m = f.manager();
    for (const args of [{ sudo: true }, { session: true }, { pty: true }, { pipefail: true }, { env: { 'bad-key': 'x' } }, { env: { X: 1 } }, { command: 'a\0b' }, { cwd: 1 }, { input: 1 }]) {
      await assert.rejects(m.startBackground('host', { command: 'true', ...args }));
    }
    assert.equal(f.calls.length, 0);
  });
  await check('acknowledged launch preserves aliases, canonical host and literal files', async () => {
    const f = fake(), m = f.manager(), command = "printf '%s' 'quote $() `literal`'\nfalse";
    const r = await m.startBackground('alias', { command, cwd: "/tmp/a ' $()\n用户", env: { VALUE: "'$()\n用户" }, input: 'stdin\n', timeoutMs: 1000, signal: new AbortController().signal });
    assert.equal(r.task_id, r.taskId); assert.equal(r.pid, '1234'); assert.equal(r.running, true);
    assert.equal(r.status, 'running'); assert.equal(r.cursor, 0); assert.match(r.logPolicy, /unbounded/);
    assert.equal(f.get(`${f.dir(r.task_id)}/command.sh`).toString(), command);
    assert.equal(f.get(`${f.dir(r.task_id)}/input`).toString(), 'stdin\n');
    assert.match(f.get(`${f.dir(r.task_id)}/environment.sh`).toString(), /export VALUE=/);
    assert(f.calls.every(c => c.host === 'host'));
    // Validate the actual generated controller with bash where available.
    const control = f.get(`${f.dir(r.task_id)}/control.sh`).toString();
    const syntax = await processRun('bash', ['-n'], control);
    if (syntax.error?.code !== 'ENOENT') assert.equal(syntax.exitCode, 0, syntax.stderr);
    assert.match(control, /tick == "\$start"/); assert.match(control, /boot ==/);
  });
  await check('launch response loss returns recoverable id and dispatches once', async () => {
    const f = fake(); f.launchFailure({ exitCode: null, stdout: '', stderr: '', timedOut: true });
    let id;
    await assert.rejects(f.manager().startBackground('host', { command: 'side_effect' }), e => {
      id = e.task_id; return e.code === 'JOB_OUTCOME_UNKNOWN' && e.status === 'unknown' && e.taskId === id;
    });
    const found = await f.manager().listBackground('host');
    assert.equal(found.jobs[0].task_id, id); assert.equal(found.jobs[0].status, 'running');
    assert.equal(f.calls.filter(c => words(c.command)[4] === 'launch').length, 1);
  });
  await check('success/failure terminal status and exit codes survive restart', async () => {
    for (const exitCode of [0, 17]) {
      const f = fake(), r = await f.manager().startBackground('host', { command: 'anything' });
      Object.assign(f.jobs.get(f.dir(r.task_id)), { status: exitCode ? 'failed' : 'succeeded', exitCode });
      const recovered = await f.manager().backgroundLogs(r.task_id);
      assert.equal(recovered.exitCode, exitCode); assert.equal(recovered.running, false);
      assert.equal(recovered.status, exitCode ? 'failed' : 'succeeded');
    }
  });
  await check('bounded short SFTP reads preserve UTF-8 and byte cursors', async () => {
    const f = fake(), m = f.manager(), r = await m.startBackground('host', { command: 'anything' });
    f.files.set(`${f.dir(r.task_id)}/output.log`, Buffer.from('ab用户🙂end'));
    let cursor = 0, content = '', truncated = false;
    do {
      const part = await m.backgroundLogs(r.task_id, { cursor, limit: 4 });
      assert(part.cursor > cursor); cursor = part.cursor; content += part.content; truncated = part.truncated;
    } while (truncated);
    assert.equal(content, 'ab用户🙂end'); assert.equal(cursor, Buffer.byteLength(content));
    assert.equal(f.handles().opened, f.handles().closed);
    assert.equal((await m.backgroundLogs(r.task_id, { cursor })).content, '');
    assert.equal((await m.backgroundLogs(r.task_id)).content, content, 'explicit cursor does not move implicit cursor');
  });
  await check('partial UTF-8 tail waits, then completes without replacement', async () => {
    const f = fake(), m = f.manager(), r = await m.startBackground('host', { command: 'anything' });
    const p = `${f.dir(r.task_id)}/output.log`, data = Buffer.from('用户');
    f.files.set(p, data.subarray(0, 2));
    assert.equal((await m.backgroundLogs(r.task_id)).cursor, 0);
    f.files.set(p, data);
    const next = await m.backgroundLogs(r.task_id);
    assert.equal(next.content, '用户'); assert.equal(next.cursor, data.length);
  });
  await check('terminal invalid UTF-8 flushes once and log shrink is explicit', async () => {
    const f = fake(), m = f.manager(), r = await m.startBackground('host', { command: 'anything' });
    f.files.set(`${f.dir(r.task_id)}/output.log`, Buffer.from([0xe4]));
    Object.assign(f.jobs.get(f.dir(r.task_id)), { status: 'failed', exitCode: 2 });
    const a = await m.backgroundLogs(r.task_id);
    assert.equal(a.content, '\ufffd'); assert.equal(a.cursor, 1);
    assert.equal((await m.backgroundLogs(r.task_id)).content, '');
    await assert.rejects(m.backgroundLogs(r.task_id, { cursor: 10 }), code('JOB_LOG_CHANGED'));
    assert.equal(f.handles().opened, f.handles().closed);
  });
  await check('queued log cancellation is prompt and preserves the serialization barrier', async () => {
    const f = fake();
    const runtime = createRuntime({ cfg: {} });
    const manager = createJobManager({ ...f.callbacks, wait: runtime.wait, check: runtime.check });
    const job = await manager.startBackground('host', { command: 'anything' });
    const exec = f.callbacks.runCommand;
    let release, statusCalls = 0;
    const blocked = new Promise(resolve => { release = resolve; });
    // The injected object was spread above, so build the polling manager after
    // replacing this callback. Its first status RPC deliberately remains active.
    f.callbacks.runCommand = async (host, args) => {
      if (words(args.command)[4] === 'status' && ++statusCalls === 1) await blocked;
      return exec(host, args);
    };
    const polling = createJobManager({ ...f.callbacks, wait: runtime.wait, check: runtime.check });
    const poll = timeoutMs => runtime.operation({ timeoutMs }, () => polling.backgroundLogs(job.task_id));
    try {
      const first = poll(1000); await sleep(0);
      await assert.rejects(poll(15), code('TIMEOUT'));
      const third = poll(1000); await sleep(0); assert.equal(statusCalls, 1);
      release(); await Promise.all([first, third]); assert.equal(statusCalls, 2);
    } finally { release(); runtime.shutdown(); }
  });
  await check('parallel implicit log polls do not duplicate bytes', async () => {
    const f = fake(), m = f.manager(), r = await m.startBackground('host', { command: 'anything' });
    f.files.set(`${f.dir(r.task_id)}/output.log`, Buffer.from('12345678'));
    const parts = await Promise.all([m.backgroundLogs(r.task_id, { limit: 4 }), m.backgroundLogs(r.task_id, { limit: 4 })]);
    assert.equal(parts.map(p => p.content).join(''), '12345678');
  });
  await check('concurrent list/stop recovery cannot reset an in-flight log cursor', async () => {
    const f = fake(), base = f.callbacks.withSftp;
    let release, reading, blocked = true;
    const entered = new Promise(resolve => { reading = resolve; });
    f.callbacks.withSftp = async (host, fn) => base(host, async s => {
      const wrapped = { ...s, fstat(p, cb) { if (!blocked) return s.fstat(p, cb); reading(); release = () => s.fstat(p, cb); } };
      return fn(wrapped);
    });
    const m = f.manager(), r = await m.startBackground('host', { command: 'anything' });
    f.files.set(`${f.dir(r.task_id)}/output.log`, Buffer.from('12345678'));
    const poll = m.backgroundLogs(r.task_id, { limit: 4 });
    await entered;
    await m.listBackground('host');
    await m.stopBackground(r.task_id);
    blocked = false;
    release();
    assert.equal((await poll).cursor, 4);
    f.callbacks.withSftp = base;
    assert.equal((await m.backgroundLogs(r.task_id, { limit: 4 })).content, '5678');
  });
  await check('stop is idempotent, logs retained, cleanup explicit', async () => {
    const f = fake(), m = f.manager(), r = await m.startBackground('host', { command: 'anything' });
    f.files.set(`${f.dir(r.task_id)}/output.log`, Buffer.from('retained'));
    const a = await m.stopBackground(r.task_id, { graceMs: 0 }), b = await m.stopBackground(r.task_id);
    assert.equal(a.status, 'stopped'); assert.equal(a.ok, true); assert.equal(b.exitCode, a.exitCode);
    assert.equal((await m.backgroundLogs(r.task_id)).content, 'retained');
    assert.equal((await m.stopBackground(r.task_id, { cleanup: true })).cleaned, true);
    assert.equal((await m.stopBackground(r.task_id, { cleanup: true })).cleaned, true);
    assert.equal(f.files.size, 0);
    await assert.rejects(m.backgroundLogs(r.task_id), code('JOB_CLEANED'));
  });
  await check('identity mismatch cannot be stopped or cleaned', async () => {
    const f = fake(), m = f.manager(), r = await m.startBackground('host', { command: 'anything' });
    Object.assign(f.jobs.get(f.dir(r.task_id)), { status: 'unknown' });
    const stopped = await m.stopBackground(r.task_id);
    assert.equal(stopped.ok, false); assert.equal(stopped.running, null);
    await assert.rejects(m.stopBackground(r.task_id, { cleanup: true }), code('JOB_NOT_TERMINAL'));
    assert(f.files.size > 0);
  });
  await check('unreachable host lists unknown, never succeeded or empty success', async () => {
    const f = fake(), m = f.manager(), r = await m.startBackground('host', { command: 'anything' });
    f.offline(true);
    const list = await m.listBackground('host');
    assert.equal(list.status, 'unknown'); assert.equal(list.jobs[0].task_id, r.task_id);
    assert.equal(list.jobs[0].running, null); assert.match(list.error, /unreachable/);
    assert.equal((await f.manager().listBackground('host')).status, 'unknown');
  });
  await check('list pagination, recovery and corrupt metadata are bounded', async () => {
    const f = fake(), m = f.manager();
    for (let i = 0; i < 3; i++) await m.startBackground('host', { command: 'anything' });
    const fresh = f.manager(), first = await fresh.listBackground('alias', { limit: 2 });
    assert.equal(first.jobs.length, 2); assert.equal(first.truncated, true);
    const last = await fresh.listBackground('host', { cursor: first.cursor, limit: 2 });
    assert.equal(last.jobs.length, 1); assert.equal(last.truncated, false);
    const id = first.jobs[0].task_id;
    f.files.set(`${f.dir(id)}/metadata.json`, Buffer.alloc(20000, 120));
    const list = await fresh.listBackground('host');
    assert.equal(list.jobs.find(t => t.task_id === id).status, 'unknown');
  });
  await check('bad ids and invalid budgets do not dispatch remote commands', async () => {
    const f = fake(), m = f.manager();
    await assert.rejects(m.backgroundLogs('../../bad'), code('JOB_INVALID_ID'));
    await assert.rejects(m.backgroundLogs('bad', { cursor: -1 }), code('JOB_INVALID_ARGUMENT'));
    await assert.rejects(m.backgroundLogs('bad', { limit: 1 }), code('JOB_INVALID_ARGUMENT'));
    await assert.rejects(m.stopBackground('bad', { graceMs: Infinity }), code('JOB_INVALID_ARGUMENT'));
    await assert.rejects(m.listBackground('host', { limit: 201 }), code('JOB_INVALID_ARGUMENT'));
    assert.equal(f.calls.length, 0);
  });
}

function processRun(file, args, input, timeout = 30000, env) {
  return new Promise(resolve => {
    const child = execFile(file, args, { timeout, maxBuffer: 4 * 1024 * 1024, env, windowsHide: true }, (error, stdout, stderr) => {
      resolve({ exitCode: error ? (typeof error.code === 'number' ? error.code : null) : 0, stdout, stderr,
        timedOut: !!error?.killed, error });
    });
    child.stdin.on('error', () => {});
    child.stdin.end(input);
  });
}

async function realChecks(docker) {
  let container, home;
  if (docker) {
    home = "/tmp/sshbridge-jobs ' $literal 用户";
    const started = await processRun('docker', ['run', '--rm', '--pull=never', '--network=none', '-d', '-e', `HOME=${home}`,
      'python:3.12-slim-bookworm', 'bash', '-c', 'mkdir -p -- "$HOME"; exec sleep 600']);
    assert.equal(started.exitCode, 0, started.stderr);
    container = started.stdout.trim();
  } else { home = await fs.mkdtemp(path.join(os.tmpdir(), 'sshbridge-jobs-')); }
  const remote = (command, input, timeout) => docker
    ? processRun('docker', ['exec', '-i', container, 'bash', '-c', command], input, timeout)
    : processRun('bash', ['-c', command], input, timeout, { ...process.env, HOME: home });
  // This filesystem adapter exists only in the test. It is not SSH, never reads
  // host configuration, and Docker has no network and no host filesystem mounts.
  const python = 'import sys,json,base64,os\na=json.load(sys.stdin)\np=a["path"]\nif a["op"]=="put":\n with open(p,"wb") as f: f.write(base64.b64decode(a["data"]))\n print("{}")\nelse:\n with open(p,"rb") as f:\n  size=os.fstat(f.fileno()).st_size\n  f.seek(a["offset"]); data=f.read(a["limit"])\n print(json.dumps({"size":size,"data":base64.b64encode(data).decode()}))';
  async function get(p, offset = 0, limit = 16384) {
    if (!docker) { const h = await fs.open(p); try { const st = await h.stat(), b = Buffer.alloc(limit); const { bytesRead } = await h.read(b, 0, limit, offset); return { size: st.size, bytes: b.subarray(0, bytesRead) }; } finally { await h.close(); } }
    const r = await remote(`python3 -I -c ${shq(python)}`, JSON.stringify({ op: 'get', path: p, offset, limit }));
    assert.equal(r.exitCode, 0, r.stderr);
    const data = JSON.parse(r.stdout); return { size: data.size, bytes: Buffer.from(data.data, 'base64') };
  }
  async function put(p, content) {
    if (!docker) return fs.writeFile(p, content);
    const r = await remote(`python3 -I -c ${shq(python)}`, JSON.stringify({ op: 'put', path: p, data: Buffer.from(content).toString('base64') }));
    assert.equal(r.exitCode, 0, r.stderr);
  }
  const sftp = {
    open(p, _m, cb) { cb(null, p); },
    fstat(p, cb) { get(p, 0, 0).then(r => cb(null, { size: r.size }), cb); },
    read(p, b, off, len, pos, cb) { get(p, pos, len).then(r => { r.bytes.copy(b, off); cb(null, r.bytes.length); }, cb); },
    close(_h, cb) { cb(); },
  };
  const callbacks = {
    shq, resolveName: n => { assert(!n || n === 'local'); return 'local'; },
    runCommand: (_n, a) => remote(a.command, undefined, a.timeoutMs),
    withSftp: async (_n, fn) => fn(sftp), writeRemoteFile: (_s, p, c) => put(p, c),
    readFrom: async (_s, p, offset, limit) => { const r = await get(p, offset, limit); return { content: r.bytes.toString(), size: offset + r.bytes.length, truncated: r.size > offset + r.bytes.length }; },
  };
  const manager = () => createJobManager(callbacks), m = manager();
  const jobs = [];
  async function start(args) { const r = await m.startBackground('local', args); jobs.push(r.task_id); return r; }
  async function terminal(id) {
    const end = Date.now() + 20000;
    while (Date.now() < end) {
      const r = await m.backgroundLogs(id, { cursor: 0 });
      if (r.running === false) return r;
      await sleep(50);
    }
    throw new Error(`job did not terminate: ${id}`);
  }
  try {
    await check('real shell: invalid cwd never launches', async () => {
      await assert.rejects(start({ command: 'true', cwd: '/sshbridge-no-such-cwd' }));
    });
    await check('real shell: literal env/input/cwd and multiline exit preserved', async () => {
      const cwd = `${home}/cwd ' $()\n用户`;
      assert.equal((await remote(`mkdir -- ${shq(cwd)}`)).exitCode, 0);
      const r = await start({ command: 'printf "%s\\n" "$VALUE" "$PWD"\ncat\nprintf "tail\\n"\nexit 17', cwd, env: { VALUE: "a'$(not-executed)用户" }, input: 'stdin🙂\n' });
      const t = await terminal(r.task_id);
      assert.equal(t.status, 'failed'); assert.equal(t.exitCode, 17);
      assert.equal(t.content, `a'$(not-executed)用户\n${cwd}\nstdin🙂\ntail\n`);
      assert.equal((await manager().backgroundLogs(r.task_id, { cursor: 0 })).content, t.content);
    });
    await check('real shell: natural success and PATH env cannot break supervisor', async () => {
      const r = await start({ command: 'printf success\ntrue', env: { PATH: '/not-a-path' } });
      const t = await terminal(r.task_id);
      assert.equal(t.status, 'succeeded'); assert.equal(t.exitCode, 0); assert.equal(t.content, 'success');
    });
    await check('real shell: command exit does not abandon live descendants', async () => {
      const r = await start({ command: 'sleep 60 &\nprintf parent-exited' });
      let t;
      for (let i = 0; i < 20; i++) { t = await m.backgroundLogs(r.task_id, { cursor: 0 }); if (t.content) break; await sleep(50); }
      assert.equal(t.content, 'parent-exited'); assert.equal(t.status, 'running');
      const stopped = await manager().stopBackground(r.task_id, { graceMs: 100 });
      assert.equal(stopped.status, 'stopped'); assert.equal(stopped.ok, true);
    });
    await check('real shell: PID starttime/boot mismatch never signals original job', async () => {
      const r = await start({ command: 'printf ready; sleep 60' });
      const dir = `${home}/.cache/ssh-bridge/jobs/${r.task_id}`, identity = (await get(`${dir}/identity`)).bytes.toString();
      const fields = identity.trim().split(' ');
      try {
        for (const altered of [`${fields[0]} 0 ${fields[2]}\n`, `${fields[0]} ${fields[1]} invalid-boot\n`]) {
          await put(`${dir}/identity`, altered);
          const stopped = await manager().stopBackground(r.task_id);
          assert.equal(stopped.status, 'unknown'); assert.equal(stopped.ok, false);
          await assert.rejects(m.stopBackground(r.task_id, { cleanup: true }), code('JOB_NOT_TERMINAL'));
          const alive = await remote(`kill -0 ${shq(fields[0])}`);
          assert.equal(alive.exitCode, 0);
        }
      } finally { await put(`${dir}/identity`, identity); }
      assert.equal((await m.stopBackground(r.task_id, { graceMs: 100 })).status, 'stopped');
    });
    await check('real shell: TERM-resistant tree escalates, idempotent stop retains logs', async () => {
      const r = await start({ command: "trap '' TERM\nbash -c 'trap \"\" TERM; while :; do sleep 1; done' &\nprintf ready\nwait" });
      for (let i = 0; i < 20; i++) { if ((await m.backgroundLogs(r.task_id, { cursor: 0 })).content === 'ready') break; await sleep(50); }
      const stopped = await m.stopBackground(r.task_id, { graceMs: 100 });
      assert.equal(stopped.status, 'stopped'); assert.equal(stopped.exitCode, 137);
      assert.equal((await m.stopBackground(r.task_id)).exitCode, 137);
      assert.equal((await m.backgroundLogs(r.task_id, { cursor: 0 })).content, 'ready');
      assert.equal((await m.stopBackground(r.task_id, { cleanup: true })).cleaned, true);
    });
    await check('real shell: interrupted stop can resume without stale locks', async () => {
      const r = await start({ command: 'printf ready; sleep 60' });
      const dir = `${home}/.cache/ssh-bridge/jobs/${r.task_id}`;
      assert.equal((await remote(`: > ${shq(`${dir}/stop.request`)}; kill -STOP ${shq(r.pid)}`)).exitCode, 0);
      assert.equal((await manager().stopBackground(r.task_id, { graceMs: 100 })).status, 'stopped');
    });
    await check('real shell: durable metadata discovery and explicit terminal cleanup', async () => {
      const list = await manager().listBackground('local');
      assert.equal(list.status, 'ok'); assert.equal(list.jobs.length, jobs.length - 1);
      for (const id of jobs) {
        const result = await m.stopBackground(id, { graceMs: 100, cleanup: true });
        assert.equal(result.cleaned, true);
      }
      assert.equal((await manager().listBackground('local')).jobs.length, 0);
    });
  } finally {
    if (docker) {
      const removed = await processRun('docker', ['rm', '-f', container]);
      assert.equal(removed.exitCode, 0, removed.stderr);
    } else {
      for (const id of jobs) await m.stopBackground(id, { graceMs: 0, cleanup: true }).catch(() => {});
      await fs.rm(home, { recursive: true, force: true });
    }
  }
}

(async () => {
  await offlineChecks();
  if (process.argv.includes('--docker')) await realChecks(true);
  else if (process.platform === 'linux') await realChecks(false);
  else console.log('# Linux shell checks not run; use --docker with the cached test image.');
  console.log(`Passed ${passed} managed-jobs checks.`);
})().catch(e => { console.error(e); process.exitCode = 1; });
