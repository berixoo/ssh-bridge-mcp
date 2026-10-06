const fs = require('fs');
const path = require('path');

// upload/download take a local path straight from the model, so without a
// boundary a prompt-injected agent can push any file on this machine to a
// remote host -- including config.json, which holds the SSH passwords in
// cleartext -- or overwrite any local file via download.

function foldCase(p) {
  return process.platform === 'win32' ? p.toLowerCase() : p;
}

function isWithin(root, target) {
  const rel = path.relative(root, target);
  return rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel));
}

// Resolve symlinks in the longest existing prefix and re-append the rest, so
// a symlink planted inside an allowed root cannot be used to reach outside it
// and a not-yet-existing download target still resolves predictably.
function resolveReal(input) {
  let current = path.resolve(input);
  const tail = [];
  for (;;) {
    try {
      const real = fs.realpathSync(current);
      return tail.length > 0 ? path.join(real, ...tail.reverse()) : real;
    } catch (err) {
      if (err.code !== 'ENOENT' && err.code !== 'ENOTDIR') throw err;
      const parent = path.dirname(current);
      if (parent === current) return path.resolve(input);
      tail.push(path.basename(current));
      current = parent;
    }
  }
}

function checkLocalPath({ localPath, cfg, configFile, tool }) {
  const resolved = resolveReal(localPath);

  // Never transferable under any policy: this file is the credentials store,
  // and "the LLM cannot read the config" is the whole point of the bridge.
  if (configFile && foldCase(resolved) === foldCase(resolveReal(configFile))) {
    throw new Error(`refusing ${tool}: that path is the ssh-bridge configuration file, which holds credentials`);
  }

  // Opt-in boundary: with no localRoots configured the bridge accepts any local
  // path, which is the original behaviour and what a dev workflow wants. Set
  // localRoots to fence it in.
  const base = configFile ? path.dirname(configFile) : process.cwd();
  const roots = (cfg.localRoots || []).map((root) => resolveReal(path.resolve(base, root)));
  if (roots.length > 0 && !roots.some((root) => isWithin(foldCase(root), foldCase(resolved)))) {
    throw new Error(
      `refusing ${tool}: local path is outside the configured localRoots (${roots.join(', ')}). ` +
        'Add the directory to "localRoots" in the server config, or remove "localRoots" to allow any path.'
    );
  }

  return resolved;
}

module.exports = { checkLocalPath, isWithin, resolveReal };
