#!/usr/bin/env node
// Opt-in real host smoke. Configuration is only loaded internally; never printed.
const assert = require('assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const { loadConfig, configPath } = require('../src/config');
const { createBridge } = require('../src/ssh');
const host = process.argv[2];
if (!process.env.SSH_BRIDGE_CONFIG || !host) throw new Error('Set SSH_BRIDGE_CONFIG and pass a configured host name; this test changes only its own temporary files/jobs');
const cfg = loadConfig();
const quote = (s) => "'" + s.replace(/'/g, "'\\''") + "'";
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
let bridge = createBridge(cfg);
let remote;
let local;
const jobs = new Set();
let passed = 0;
async function test(label, fn) { await fn(); passed++; console.log('PASS ' + label); }
async function command(text, options = {}) {
  const r = await bridge.runCommand(host, { command: text, timeoutMs: 15000, ...options });
  assert.equal(r.timedOut, false); assert.equal(r.exitCode, 0, `command failed: ${r.stderr}`); return r;
}
async function terminal(id) {
  for (let n = 0; n < 80; n++) {
    const r = await bridge.backgroundLogs(id, { cursor: 0 });
    if (r.running === false) return r;
    if (r.status === 'unknown') throw new Error('managed task status became unknown');
    await delay(100);
  }
  throw new Error('job did not reach terminal status');
}
function get(url) {
  return new Promise((resolve, reject) => {
    const request = http.get(url, (res) => { let text = ''; res.setEncoding('utf8'); res.on('data', (s) => { text += s; }); res.on('end', () => resolve({ code: res.statusCode, text })); });
    request.setTimeout(5000, () => request.destroy(new Error('HTTP tunnel deadline'))); request.on('error', reject);
  });
}
async function main() {
  try {
    await test('SSH executes and creates an isolated remote test directory', async () => {
      remote = (await command('mktemp -d /tmp/ssh-bridge-smoke-XXXXXXXX')).stdout.trim();
      assert.match(remote, /^\/tmp\/ssh-bridge-smoke-[A-Za-z0-9]+$/);
      const root = cfg.localRoots?.length ? path.resolve(path.dirname(configPath()), cfg.localRoots[0]) : os.tmpdir();
      local = fs.mkdtempSync(path.join(root, '.ssh-bridge-smoke-'));
    });
    await test('sudo keeps pipefail/env and server-owned password handling', async () => {
      const r = await command('printf "%s " "$BRIDGE_CHECK"; id -u', { sudo: true, env: { BRIDGE_CHECK: 'sudo-ok' }, pipefail: true });
      assert.equal(r.stdout.trim(), 'sudo-ok 0');
    });
    await test('persistent bash preserves cwd/env/functions/aliases and final failure', async () => {
      await command('export BRIDGE_PERSIST=state; bridge_fn() { printf "$BRIDGE_PERSIST"; }; alias bridge_alias="printf alias"', { session: true, cwd: remote });
      const r = await command('bridge_fn; bridge_alias; pwd', { session: true });
      assert.equal(r.stdout.trim(), 'statealias' + remote);
      const fail = await bridge.runCommand(host, { command: 'printf before\nfalse', session: true }); assert.equal(fail.exitCode, 1);
      await bridge.closeShell(host);
    });
    await test('concurrent exec and SFTP share a healthy pool', async () => {
      const results = await Promise.all(Array.from({ length: 16 }, (_, i) => i % 2 ? bridge.listDir(host, remote) : command('printf parallel')));
      assert.equal(results.length, 16);
    });
    await test('UTF8 staging, scoped ranges, hash conflict and exact patch', async () => {
      const file = remote + '/text.txt';
      await bridge.writeFile(host, file, '﻿first\r\n中文\r\nlast\r\n');
      const read = await bridge.readFile(host, file); assert.equal(read.hash_scope, 'whole_file');
      assert.equal((await bridge.readFile(host, file, { start_line: 2, end_line: 2 })).content, '中文\r\n');
      await bridge.patchFile(host, file, { expected_hash: read.sha256, edits: [{ old_text: '中文', new_text: '更新' }] });
      await assert.rejects(bridge.patchFile(host, file, { expected_hash: read.sha256, edits: [{ old_text: 'first', new_text: 'bad' }] }), { code: 'FILE_CONFLICT' });
      assert.equal((await bridge.readFile(host, file)).content, '﻿first\r\n更新\r\nlast\r\n');
    });
    await test('2MiB binary and empty files round-trip through protected staging', async () => {
      for (const size of [2 * 1024 * 1024, 0]) {
        const bytes = crypto.randomBytes(size); const source = path.join(local, 'source.bin'); const target = path.join(local, 'result.bin');
        fs.writeFileSync(source, bytes); fs.writeFileSync(target, 'old');
        await bridge.upload(host, source, remote + '/binary.bin'); await bridge.download(host, remote + '/binary.bin', target);
        assert.deepEqual(fs.readFileSync(target), bytes);
      }
      await assert.rejects(bridge.upload(host, configPath(), remote + '/forbidden'), /configuration file/);
    });
    await test('managed jobs have truthful success/failure, UTF8 logs and invalid cwd rejection', async () => {
      for (const code of [0, 7]) {
        const job = await bridge.startBackground(host, { command: `printf '中文'; exit ${code}`, cwd: remote }); jobs.add(job.task_id);
        const r = await terminal(job.task_id); assert.equal(r.exitCode, code); assert.equal(r.content, '中文'); assert.equal(r.status, code ? 'failed' : 'succeeded');
      }
      await assert.rejects(bridge.startBackground(host, { command: 'true', cwd: remote + '/missing' }));
    });
    await test('job metadata and logs recover after bridge restart', async () => {
      const id = [...jobs][0]; await bridge.close(); bridge = createBridge(cfg);
      assert.equal((await bridge.backgroundLogs(id, { cursor: 0 })).content, '中文');
      assert.ok((await bridge.listBackground(host)).jobs.some((j) => j.task_id === id));
    });
    await test('managed stop terminates an owned TERM-resistant process tree', async () => {
      const job = await bridge.startBackground(host, { command: "trap '' TERM; sleep 300 & wait", cwd: remote }); jobs.add(job.task_id);
      const r = await bridge.stopBackground(job.task_id, { graceMs: 100 }); assert.equal(r.status, 'stopped'); assert.equal(r.running, false);
      assert.equal((await bridge.stopBackground(job.task_id)).status, 'stopped');
    });
    await test('local TCP forwarding reaches a managed remote HTTP server', async () => {
      await bridge.writeFile(host, remote + '/index.html', 'tunnel-ok');
      const script = "import http.server; s=http.server.ThreadingHTTPServer(('127.0.0.1',0),http.server.SimpleHTTPRequestHandler); print(s.server_address[1],flush=True); s.serve_forever()";
      const job = await bridge.startBackground(host, { command: 'python3 -u -c ' + quote(script), cwd: remote }); jobs.add(job.task_id);
      let port;
      for (let n = 0; n < 50; n++) { const r = await bridge.backgroundLogs(job.task_id, { cursor: 0 }); port = Number(r.content.trim()); if (port > 0) break; await delay(100); }
      assert.ok(port > 0);
      const tunnel = await bridge.openTunnel(host, { remote_port: port });
      try { const r = await get(`http://${tunnel.local_host}:${tunnel.local_port}/`); assert.equal(r.code, 200); assert.equal(r.text, 'tunnel-ok'); }
      finally { await bridge.closeTunnel(tunnel.tunnel_id); await bridge.closeTunnel(tunnel.tunnel_id); }
    });
  } finally {
    const errors = [];
    for (const id of jobs) { try { await bridge.stopBackground(id, { cleanup: true }); } catch (e) { errors.push('job cleanup: ' + e.message); } }
    if (remote) { try { await command('rm -rf -- ' + quote(remote)); } catch (e) { errors.push('remote cleanup: ' + e.message); } }
    await bridge.close(); if (local) fs.rmSync(local, { recursive: true, force: true });
    if (errors.length) throw new Error(errors.join('; '));
  }
  console.log(`VM smoke ${host}: ${passed} passed; owned files/jobs/tunnels cleaned`);
}
main().catch((e) => { console.error(e.message); process.exitCode = 1; });
