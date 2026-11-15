#!/usr/bin/env node
// Real stdio MCP child + real loopback SSH transport; no VM or private config.
const assert = require('assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const { once } = require('events');
const { Server } = require('ssh2');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');
const listen = async (s) => { s.listen(0, '127.0.0.1'); await once(s, 'listening'); return s.address().port; };
const close = (s) => new Promise((r) => s.close(r));
const decoded = (r) => JSON.parse(r.content[0].text);
let pass = 0;
async function test(label, fn) { await fn(); pass++; console.log('PASS ' + label); }
async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-bridge-mcp-protocol-'));
  const sockets = new Set();
  const peers = new Set();
  let dispatched = 0;
  let held;
  let started;
  const ssh = new Server({ hostKeys: [crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' })] }, (peer) => {
    peers.add(peer); peer.on('error', () => {}); peer.on('close', () => peers.delete(peer));
    peer.on('authentication', (ctx) => ctx.accept());
    peer.on('ready', () => {
      peer.on('session', (accept) => {
        const session = accept();
        session.on('exec', (acceptExec, _reject, info) => {
          const stream = acceptExec(); stream.on('error', () => {});
          stream.on('data', () => {}); // Drain stdin.
          if (info.command.includes('MCP_HANG')) { dispatched++; held = stream; started?.(); return; }
          if (info.command.includes('MCP_LOST')) { dispatched++; stream.write('side effect already happened'); stream.close(); return; }
          stream.write(Buffer.from('中文 protocol ok')); stream.exit(info.command.includes('MCP_FAIL') ? 7 : 0); stream.end();
        });
      });
      peer.on('tcpip', (accept, _reject, info) => {
        const upstream = net.connect(info.destPort, info.destIP); sockets.add(upstream);
        upstream.on('error', () => stream?.destroy());
        upstream.on('close', () => sockets.delete(upstream));
        const stream = accept(); stream.on('error', () => upstream.destroy());
        stream.pipe(upstream).pipe(stream);
      });
    });
  });
  const echo = net.createServer((s) => { sockets.add(s); s.on('error', () => {}); s.on('close', () => sockets.delete(s)); s.pipe(s); });
  let client;
  try {
    const port = await listen(ssh);
    const echoPort = await listen(echo);
    const fixture = path.join(tmp, 'fixture.json');
    fs.writeFileSync(fixture, JSON.stringify({ default: 'fixture', hosts: { fixture: { host: '127.0.0.1', port, user: 'test' } } }));
    const transport = new StdioClientTransport({ command: process.execPath, args: [path.resolve(__dirname, '../src/server.js')],
      env: { ...process.env, SSH_BRIDGE_CONFIG: fixture }, stderr: 'pipe' });
    transport.stderr.on('data', () => {});
    client = new Client({ name: 'ssh-bridge-selfcheck', version: '1.0.0' });
    await client.connect(transport);
    const call = (name, args, options) => client.callTool({ name, arguments: args }, undefined, options);
    await test('all new tools and end-to-end timeout schemas are registered', async () => {
      const { tools } = await client.listTools();
      for (const name of ['patch_file', 'list_background', 'open_tunnel', 'list_tunnels', 'close_tunnel']) assert.ok(tools.some((t) => t.name === name));
      assert.ok(tools.every((t) => t.inputSchema.properties.timeout_ms));
      const schema = (n) => tools.find((t) => t.name === n).inputSchema.properties;
      assert.ok(schema('stop_background').grace_ms); assert.ok(schema('background_logs').limit); assert.ok(schema('start_background').input);
    });
    await test('stdio stdout stays valid; host list has no credentials', async () => {
      const r = await call('list_hosts', {}); assert.equal(r.isError, undefined);
      assert.deepEqual(Object.keys(decoded(r)[0]).sort(), ['host', 'name', 'port', 'user']);
    });
    await test('real SSH command output, UTF8 and nonzero code are regular results', async () => {
      const r = await call('run_command', { command: 'MCP_FAIL' }); assert.equal(r.isError, undefined);
      assert.equal(decoded(r).exitCode, 7); assert.equal(decoded(r).stdout, '中文 protocol ok');
    });
    await test('operational failures and legacy taskId aliases are structured errors', async () => {
      const r = await call('run_command', { host: 'missing', command: 'true' }); assert.equal(r.isError, true); assert.ok(decoded(r).error.code);
      for (const name of ['background_logs', 'stop_background']) {
        const e = await call(name, { taskId: 'bad-id' }); assert.equal(e.isError, true); assert.equal(decoded(e).error.code, 'JOB_INVALID_ID');
      }
    });
    await test('post-dispatch close is isError/unknown and not replayed', async () => {
      const before = dispatched; const r = await call('run_command', { command: 'MCP_LOST' });
      assert.equal(r.isError, true); assert.equal(decoded(r).outcome, 'unknown'); assert.equal(dispatched, before + 1);
      assert.equal(decoded(r).stdout, 'side effect already happened');
    });
    await test('command deadline returns truthful timedOut rather than success', async () => {
      const r = await call('run_command', { command: 'MCP_HANG', timeout_ms: 150 });
      assert.equal(r.isError, true); assert.equal(decoded(r).timedOut, true);
      assert.equal(decoded(r).termination, 'best_effort');
    });
    await test('MCP cancellation reaches the live SSH channel', async () => {
      const controller = new AbortController();
      const ready = new Promise((r) => { started = r; });
      const p = call('run_command', { command: 'MCP_HANG', timeout_ms: 5000 }, { signal: controller.signal });
      await ready;
      const closed = once(held, 'close'); controller.abort();
      await assert.rejects(p); await Promise.race([closed, new Promise((_, reject) => { const t = setTimeout(() => reject(new Error('cancel did not close remote channel')), 2000); t.unref(); })]);
      started = null;
    });
    await test('MCP tunnel carries binary data and close is idempotent', async () => {
      const r = decoded(await call('open_tunnel', { remote_port: echoPort }));
      const socket = net.connect(r.local_port, r.local_host); sockets.add(socket); socket.on('error', () => {});
      await once(socket, 'connect'); const received = once(socket, 'data'); const bytes = Buffer.from([0, 255, 128, 2]); socket.write(bytes);
      assert.deepEqual((await received)[0], bytes); socket.destroy();
      assert.equal(decoded(await call('list_tunnels', {})).length, 1);
      assert.equal(decoded(await call('close_tunnel', { tunnel_id: r.tunnel_id })).closed, true);
      assert.equal(decoded(await call('close_tunnel', { tunnel_id: r.tunnel_id })).closed, true);
      assert.equal(decoded(await call('list_tunnels', {})).length, 0);
    });
  } finally {
    await client?.close(); for (const s of sockets) s.destroy(); for (const p of peers) p.end();
    await Promise.all([close(ssh), close(echo)]); fs.rmSync(tmp, { recursive: true, force: true });
  }
  console.log(`MCP stdio checks: ${pass} passed`);
}
main().catch((e) => { console.error(e); process.exitCode = 1; });
