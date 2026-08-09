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
