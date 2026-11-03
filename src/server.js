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
    console.error(`[ssh-bridge-mcp] localRoots "${root}" does not exist (${absolute}); paths under it will be refused`);
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
    pipefail: z.boolean().optional().default(false).describe('fail when any stage of a pipeline fails; catches `cmd | head` masking a real error'),
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
  description: 'Read a text file on the remote host (small files only, hard limit 500 KB; use download for large).',
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
  description: 'Upload a local (Windows) file to a remote POSIX path via SFTP. Creates remote directories. If the server configures localRoots, local_path must lie inside one of them.',
  inputSchema: { host: hostSchema, local_path: z.string().min(1), remote_path: z.string().min(1) },
}, async (args) => {
  try { return ok(await bridge.upload(args.host, args.local_path, args.remote_path)); } catch (e) { throw toolError(e); }
});

server.registerTool('download', {
  description: 'Download a remote file to a local (Windows) path via SFTP. Refuses files larger than maxDownloadBytes (config, default 2 GiB); if localRoots is configured, local_path must lie inside one of them.',
  inputSchema: { host: hostSchema, remote_path: z.string().min(1), local_path: z.string().min(1) },
}, async (args) => {
  try { return ok(await bridge.download(args.host, args.remote_path, args.local_path)); } catch (e) { throw toolError(e); }
});

server.registerTool('list_dir', {
  description: 'List a remote directory via SFTP. Returns entries with name, type (file/dir/link), size, mtime and mode. Directories sort first. Use this instead of shelling out to ls.',
  inputSchema: { host: hostSchema, path: z.string().min(1).describe('remote directory') },
}, async (args) => {
  try { return ok(await bridge.listDir(args.host, args.path)); } catch (e) { throw toolError(e); }
});

server.registerTool('search_files', {
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

server.registerTool('rename', {
  description: 'Move or rename a path on the remote host via SFTP. Creates the destination parent directory.',
  inputSchema: { host: hostSchema, from: z.string().min(1), to: z.string().min(1) },
}, async (args) => {
  try { return ok(await bridge.renamePath(args.host, args.from, args.to)); } catch (e) { throw toolError(e); }
});

server.registerTool('delete', {
  description: 'Delete a file, symlink, or empty directory on the remote host via SFTP. Destructive: set recursive=true to remove a directory tree (symlinks inside are unlinked, never followed).',
  inputSchema: {
    host: hostSchema,
    path: z.string().min(1),
    recursive: z.boolean().optional().default(false),
  },
}, async (args) => {
  try { return ok(await bridge.deletePath(args.host, args.path, { recursive: args.recursive })); } catch (e) { throw toolError(e); }
});

server.registerTool('screenshot', {
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
  description: 'Read new log output since the last call for a background task. Returns { content, running, truncated }. truncated:true means more output is already waiting -- call again to get it.',
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
