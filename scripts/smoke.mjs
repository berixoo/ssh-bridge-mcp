import { spawn } from 'node:child_process';

const child = spawn('node', ['src/server.js'], {
  cwd: process.cwd(),
  env: { ...process.env, SSH_BRIDGE_CONFIG: 'tests/fixtures/config.test.json' },
  stdio: ['pipe', 'pipe', 'inherit'],
});
let buf = '';
let pending = new Map();
let nextId = 1;

child.on('exit', (code) => {
  console.error(`SMOKE FAIL: server exited early (code ${code})`);
  process.exit(1);
});
child.on('error', (err) => {
  console.error(`SMOKE FAIL: spawn error: ${err.message}`);
  process.exit(1);
});

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
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timeout waiting for response to ${method}`)), 5000);
    pending.set(id, (msg) => { clearTimeout(timer); resolve(msg); });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
}

try {
  await call('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'smoke', version: '0' } });
  const list = await call('tools/list', {});
  const names = list.result.tools.map((t) => t.name).sort();
  const expected = ['list_hosts', 'run_command', 'read_file', 'write_file', 'upload', 'download', 'start_background', 'background_logs', 'stop_background'].sort();
  if (JSON.stringify(names) !== JSON.stringify(expected)) {
    console.error('SMOKE FAIL: tools mismatch');
    console.error('got:', names);
    process.exit(1);
  }
  console.log('SMOKE OK: 9 tools registered');
} catch (err) {
  console.error(`SMOKE FAIL: ${err.message}`);
  process.exit(1);
}
child.kill();
process.exit(0);
