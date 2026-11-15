#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { z } = require('zod');
const { createBridge } = require('./ssh');
const { loadConfig, configPath } = require('./config');

const cfg = loadConfig();
const bridge = createBridge(cfg);

// Neither check is on by default (see README "安全边界"). Say so once at
// startup so a permissive bridge is never silently permissive.
const cfgFile = configPath();
const roots = cfg.localRoots || [];
for (const root of roots) {
  const absolute = path.resolve(path.dirname(cfgFile), root);
  if (!fs.existsSync(absolute)) {
    console.error(`[ssh-bridge-mcp] localRoots "${root}" does not exist (${absolute}); it is not created at startup; transfers still use normal path checks`);
  }
}
const verifiesHostKeys =
  (cfg.hostKeyPolicy && cfg.hostKeyPolicy !== 'insecure') ||
  Object.values(cfg.hosts).some((h) => (h.hostKeyPolicy && h.hostKeyPolicy !== 'insecure') || h.hostKeyFingerprint);
if (!verifiesHostKeys && roots.length === 0) {
  console.error(
    '[ssh-bridge-mcp] permissive defaults: host keys are not verified and upload/download accept any local ' +
      'path. See the "安全边界" section of README.md for hostKeyPolicy / localRoots.'
  );
}

const server = new McpServer({ name: 'ssh-bridge-mcp', version: require('../package.json').version });

const hostSchema = z.string().optional().describe('host name from config; defaults to configured default host');
const ok = (data) => ({ content: [{ type: 'text', text: JSON.stringify(data) }],
  ...(data?.outcome === 'unknown' || data?.status === 'unknown' || data?.timedOut ? { isError: true } : {}) });
const toolError = (e) => e;
const timeoutSchema = z.number().int().min(1).max(600000).optional().describe('End-to-end deadline including queue/connection; default 60s (command 30s, screenshot 90s)');
const registerTool = (name, definition, handler) => server.registerTool(name, {
  ...definition, inputSchema: { timeout_ms: timeoutSchema, ...definition.inputSchema },
}, async (args, extra) => {
  try {
    return await bridge.withOperation({ signal: extra?.signal,
      timeoutMs: args.timeout_ms ?? (name === 'run_command' ? 30000 : name === 'screenshot' ? 90000 : 60000) }, () => handler(args, extra));
  } catch (e) {
    return { isError: true, content: [{ type: 'text', text: JSON.stringify({
      error: { code: typeof e.code === 'string' ? e.code : 'OPERATION_FAILED', message: e.message || String(e),
        ...(typeof e.code === 'number' ? { sftp_status: e.code } : {}),
        ...(e.task_id ? { task_id: e.task_id, taskId: e.taskId, host: e.host, status: e.status } : {}),
        ...(e.cleanup_error ? { cleanup_error: e.cleanup_error } : {}) },
    }) }] };
  }
});

registerTool('list_hosts', {
  description: 'List available SSH hosts (name, host, port, user). No credentials are shown.',
  inputSchema: {},
}, async () => ok(bridge.listHosts()));

registerTool('run_command', {
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
    pipefail: z.boolean().optional().describe('Enable/disable bash pipefail; one-shot default false, session preserves its existing setting when omitted'),
    session: z.boolean().optional().default(false).describe('run in serialized persistent bash; cwd/env/functions survive. Does not support sudo, input or pty. Not an interactive REPL.'),
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

registerTool('read_file', {
  description: 'Read UTF-8 text. Default: whole file up to 500 KiB with whole-file SHA256. Optional bounded line ranges/head/tail return explicitly scoped hashes and truncation metadata.',
  inputSchema: { host: hostSchema, path: z.string().min(1),
    start_line: z.number().int().min(1).optional(), end_line: z.number().int().min(1).optional(),
    head: z.number().int().min(1).optional(), tail: z.number().int().min(1).optional(),
    max_bytes: z.number().int().min(1).max(512000).optional(),
  },
}, async (args) => {
  try { return ok(await bridge.readFile(args.host, args.path, args)); } catch (e) { throw toolError(e); }
});

registerTool('write_file', {
  description: 'Write text content to a remote file, creating parent directories.',
  inputSchema: { host: hostSchema, path: z.string().min(1), content: z.string() },
}, async (args) => {
  try { return ok(await bridge.writeFile(args.host, args.path, args.content)); } catch (e) { throw toolError(e); }
});

registerTool('upload', {
  description: 'Upload a local (Windows) file to a remote POSIX path via SFTP. Creates remote directories. If the server configures localRoots, local_path must lie inside one of them.',
  inputSchema: { host: hostSchema, local_path: z.string().min(1), remote_path: z.string().min(1) },
}, async (args) => {
  try { return ok(await bridge.upload(args.host, args.local_path, args.remote_path)); } catch (e) { throw toolError(e); }
});

registerTool('download', {
  description: 'Download a remote file to a local (Windows) path via SFTP. Refuses files larger than maxDownloadBytes (config, default 2 GiB); if localRoots is configured, local_path must lie inside one of them.',
  inputSchema: { host: hostSchema, remote_path: z.string().min(1), local_path: z.string().min(1) },
}, async (args) => {
  try { return ok(await bridge.download(args.host, args.remote_path, args.local_path)); } catch (e) { throw toolError(e); }
});

registerTool('list_dir', {
  description: 'List a remote directory via SFTP. Returns entries with name, type (file/dir/link), size, mtime and mode. Directories sort first. Use this instead of shelling out to ls.',
  inputSchema: { host: hostSchema, path: z.string().min(1).describe('remote directory') },
}, async (args) => {
  try { return ok(await bridge.listDir(args.host, args.path)); } catch (e) { throw toolError(e); }
});

registerTool('search_files', {
  description: 'Search file contents on the remote host (grep). Returns [{ file, line, text }]. Exit code 1 (no matches) is a normal empty result, not an error.',
  inputSchema: {
    host: hostSchema,
    pattern: z.string().min(1).describe('regex by default; set fixed=true for a literal string'),
    path: z.string().optional().describe('directory or file to search; default "."'),
    glob: z.string().optional().describe('limit files, e.g. "*.js" or "*.{ts,tsx}"'),
    max_results: z.number().int().min(1).max(1000).optional().describe('default 100'),
    ignore_case: z.boolean().optional().default(false),
    fixed: z.boolean().optional().default(false).describe('treat pattern as a literal string'),
  },
}, async (args) => {
  try {
    return ok(await bridge.searchFiles(args.host, {
      pattern: args.pattern,
      path: args.path,
      glob: args.glob,
      maxResults: args.max_results,
      ignoreCase: args.ignore_case,
      fixed: args.fixed,
    }));
  } catch (e) { throw toolError(e); }
});

registerTool('rename', {
  description: 'Move or rename a path on the remote host via SFTP. Creates the destination parent directory.',
  inputSchema: { host: hostSchema, from: z.string().min(1), to: z.string().min(1) },
}, async (args) => {
  try { return ok(await bridge.renamePath(args.host, args.from, args.to)); } catch (e) { throw toolError(e); }
});

registerTool('delete', {
  description: 'Delete a file, symlink, or empty directory on the remote host via SFTP. Destructive: set recursive=true to remove a directory tree (symlinks inside are unlinked, never followed).',
  inputSchema: {
    host: hostSchema,
    path: z.string().min(1),
    recursive: z.boolean().optional().default(false),
  },
}, async (args) => {
  try { return ok(await bridge.deletePath(args.host, args.path, { recursive: args.recursive })); } catch (e) { throw toolError(e); }
});

registerTool('screenshot', {
  description: 'Capture the remote host\'s desktop and return it as an image. Finds the logged-in graphical session itself, so no DISPLAY is needed. Works with GNOME/Wayland (gnome-screenshot over Xwayland), wlroots/sway (grim), and X11 (scrot/imagemagick). Downscaled to max_width and re-encoded as JPEG when ImageMagick is available.',
  inputSchema: {
    host: hostSchema,
    max_width: z.number().int().min(0).max(8000).optional().describe('downscale to this width; 0 = keep original. default 1600'),
    quality: z.number().int().min(1).max(100).optional().describe('JPEG quality when downscaling. default 82'),
  },
}, async (args) => {
  try {
    const shot = await bridge.screenshot(args.host, {
      maxWidth: args.max_width === undefined ? 1600 : args.max_width,
      quality: args.quality === undefined ? 82 : args.quality,
    });
    return {
      content: [
        { type: 'image', data: shot.base64, mimeType: shot.mimeType },
        {
          type: 'text',
          text: JSON.stringify({
            ok: true,
            bytes: shot.bytes,
            mimeType: shot.mimeType,
            optimized: shot.optimized,
            tool: shot.tool,
            sessionType: shot.sessionType,
            display: shot.display,
          }),
        },
      ],
    };
  } catch (e) { throw toolError(e); }
});

registerTool('persistent_shell_close', {
  description: 'Close the persistent shell for a host (opened by run_command with session:true). Its cwd/env state is discarded; the next session call starts a fresh shell.',
  inputSchema: { host: hostSchema },
}, async (args) => {
  try { return ok(await bridge.closeShell(args.host)); } catch (e) { throw toolError(e); }
});

registerTool('start_background', {
  description: 'Start an acknowledged Linux managed job; returns task_id/taskId and status. Supports cwd/env/input, persists remote metadata across MCP restart. Disk logs are unbounded until explicit terminal cleanup. sudo:true is unsupported; explicit noninteractive sudo in command is allowed.',
  inputSchema: {
    host: hostSchema,
    command: z.string().min(1),
    cwd: z.string().optional(),
    env: z.record(z.string(), z.string()).optional(),
    input: z.string().optional(),
    sudo: z.boolean().optional().default(false).describe('Only false is supported for managed jobs; use run_command for server-handled sudo'),
  },
}, async (args) => {
  const { host, timeout_ms, ...options } = args;
  try { return ok(await bridge.startBackground(host, options)); } catch (e) { throw toolError(e); }
});

registerTool('background_logs', {
  description: 'Read new log output since the last call for a background task. Returns { content, running, truncated }. truncated:true means more output is already waiting -- call again to get it.',
  // taskId is accepted as an alias: start_background used to return camelCase,
  // so a model that copied that key back should not get a validation error.
  inputSchema: { task_id: z.string().min(1).optional(), taskId: z.string().min(1).optional(),
    cursor: z.number().int().min(0).optional(), limit: z.number().int().min(4).max(1048576).optional() },
}, async (args) => {
  const id = args.task_id || args.taskId;
  if (!id) throw new Error('background_logs requires task_id (returned by start_background)');
  try { return ok(await bridge.backgroundLogs(id, args)); } catch (e) { throw toolError(e); }
});

registerTool('stop_background', {
  description: 'Stop a verified managed Linux session tree with TERM then KILL after grace_ms. cleanup:true removes only confirmed terminal job artifacts; repeated stop is safe.',
  inputSchema: { task_id: z.string().min(1).optional(), taskId: z.string().min(1).optional(),
    grace_ms: z.number().int().min(0).max(30000).optional(), cleanup: z.boolean().optional() },
}, async (args) => {
  const id = args.task_id || args.taskId;
  if (!id) throw new Error('stop_background requires task_id (returned by start_background)');
  try { return ok(await bridge.stopBackground(id, { graceMs: args.grace_ms, cleanup: args.cleanup })); } catch (e) { throw toolError(e); }
});

registerTool('patch_file', {
  description: 'Apply unique literal replacements to a bounded UTF-8 file only when expected_hash matches the whole-file SHA256. Optimistic conflict detection, not filesystem CAS. dry_run previews without writing.',
  inputSchema: { host: hostSchema, path: z.string().min(1), expected_hash: z.string().regex(/^[a-fA-F0-9]{64}$/),
    edits: z.array(z.object({ old_text: z.string().min(1), new_text: z.string() })).min(1), dry_run: z.boolean().optional().default(false) },
}, async (args) => ok(await bridge.patchFile(args.host, args.path, args)));

registerTool('list_background', {
  description: 'List managed jobs and recover remote job metadata after MCP restart. Unreachable hosts are unknown, not completed.',
  inputSchema: { host: hostSchema, cursor: z.number().int().min(0).optional(), limit: z.number().int().min(1).max(200).optional() },
}, async (args) => ok(await bridge.listBackground(args.host, args)));

registerTool('open_tunnel', {
  description: 'Forward a local TCP listener over SSH to remote_host:remote_port. Loopback default; local_port 0 auto-selects. Process-local, no traffic replay or restart recovery.',
  inputSchema: { host: hostSchema, remote_port: z.number().int().min(1).max(65535), remote_host: z.string().min(1).optional(),
    local_port: z.number().int().min(0).max(65535).optional(), local_host: z.string().min(1).optional() },
}, async (args) => ok(await bridge.openTunnel(args.host, args)));
registerTool('list_tunnels', {
  description: 'List local forwarding listeners owned by this MCP process.', inputSchema: { host: hostSchema },
}, async (args) => ok(await bridge.listTunnels(args.host)));
registerTool('close_tunnel', {
  description: 'Close a forwarding listener and its active streams. Idempotent.', inputSchema: { tunnel_id: z.string().min(1) },
}, async (args) => ok(await bridge.closeTunnel(args.tunnel_id)));

let closing = false;
async function shutdown() {
  if (closing) return;
  closing = true;
  await bridge.close();
  await server.close();
}
process.on('SIGINT', () => shutdown().finally(() => process.exit(0)));
process.on('SIGTERM', () => shutdown().finally(() => process.exit(0)));
process.stdin.on('end', () => shutdown().catch(() => {}));

const transport = new StdioServerTransport();
server.connect(transport).catch((e) => {
  console.error(`[ssh-bridge-mcp] fatal: ${e.message}`);
  process.exit(1);
});
