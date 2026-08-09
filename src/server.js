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
    timeout_ms: z.number().int().min(1).max(600000).optional().describe('default 30000'),
    sudo: z.boolean().optional().default(false),
    pty: z.boolean().optional().default(false),
    env: z.record(z.string(), z.string()).optional(),
    input: z.string().optional().describe('one-shot stdin, written then closed'),
  },
}, async (args) => {
  try {
    const bridgeArgs = { ...args };
    if (args.timeout_ms !== undefined) {
      bridgeArgs.timeoutMs = args.timeout_ms;
      delete bridgeArgs.timeout_ms;
    }
    return ok(await bridge.runCommand(args.host, bridgeArgs));
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
