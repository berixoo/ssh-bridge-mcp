const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

// ssh2 auto-accepts any host key when connect() gets no hostVerifier, so the
// server would hand the configured password to whoever answers on the target
// address. Everything here exists to give hostVerifier something to check
// against: OpenSSH's known_hosts format, so keys can be seeded with
// `ssh-keyscan` and inspected with `ssh-keygen -F`.

// OpenSSH SHA256 fingerprint: base64(sha256(blob)), '=' padding stripped.
function keyFingerprint(blob) {
  return 'SHA256:' + crypto.createHash('sha256').update(blob).digest('base64').replace(/=+$/, '');
}

function normalizeFingerprint(value) {
  return String(value).trim().replace(/^SHA256:/i, '').replace(/=+$/, '');
}

// A host key blob opens with its type as a length-prefixed string
// ("ssh-ed25519", "ssh-rsa", ...) -- the same token known_hosts stores in its
// second column.
function keyTypeOf(blob) {
  if (!Buffer.isBuffer(blob) || blob.length < 4) return null;
  const n = blob.readUInt32BE(0);
  if (n <= 0 || 4 + n > blob.length) return null;
  const type = blob.subarray(4, 4 + n).toString('ascii');
  return /^[a-z0-9@.-]+$/.test(type) ? type : null;
}

function hostName(host, port) {
  return port === 22 ? host : `[${host}]:${port}`;
}

function globToRegExp(pattern) {
  let re = '';
  for (const ch of pattern) {
    if (ch === '*') re += '.*';
    else if (ch === '?') re += '.';
    else re += ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

// Hashed entries look like |1|<base64 salt>|<base64 hmac-sha1>. HashKnownHosts
// is on by default in several distros, so a known_hosts written by a normal
// ssh session is likely to be hashed and would never match a plain compare.
function hashedPatternMatches(pattern, name) {
  const parts = pattern.split('|');
  if (parts.length !== 4 || parts[0] !== '' || parts[1] !== '1') return false;
  const salt = Buffer.from(parts[2], 'base64');
  const expected = parts[3].replace(/=+$/, '');
  const actual = crypto.createHmac('sha1', salt).update(name).digest('base64').replace(/=+$/, '');
  return actual === expected;
}

function matchOne(pattern, name) {
  if (pattern.startsWith('|')) return hashedPatternMatches(pattern, name);
  return globToRegExp(pattern).test(name);
}

// A hostnames field is a comma-separated list; a leading '!' negates, and any
// matching negation vetoes the whole line (OpenSSH semantics).
function patternsMatch(patterns, name) {
  let matched = false;
  for (const pattern of patterns) {
    if (!pattern) continue;
    if (pattern.startsWith('!')) {
      if (matchOne(pattern.slice(1), name)) return false;
    } else if (!matched && matchOne(pattern, name)) {
      matched = true;
    }
  }
  return matched;
}

function parseLine(line) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) return null;
  const fields = trimmed.split(/\s+/);
  const markers = [];
  let i = 0;
  while (i < fields.length && fields[i].startsWith('@')) markers.push(fields[i++]);
  const patternField = fields[i++];
  const keyType = fields[i++];
  const keyB64 = fields[i++];
  if (!patternField || !keyType || !keyB64) return null;
  const blob = Buffer.from(keyB64, 'base64');
  if (blob.length === 0) return null;
  return { markers, patterns: patternField.split(','), keyType, blob };
}

function defaultKnownHostsPaths(configFile) {
  const paths = [path.join(path.dirname(configFile), 'known_hosts')];
  // Reuse keys OpenSSH already trusts rather than re-prompting for hosts the
  // user has connected to from a shell. Read-only: entries learned here are
  // never written back to it.
  const openssh = path.join(os.homedir(), '.ssh', 'known_hosts');
  if (fs.existsSync(openssh)) paths.push(openssh);
  return paths;
}

function createKnownHostsStore(paths) {
  const readPaths = paths.slice();
  const writePath = readPaths[0];
  const warned = new Set();

  function readAll() {
    const out = [];
    for (const file of readPaths) {
      let text;
      // Re-read on every lookup (files are small and hand-editing them while
      // the server runs should take effect) -- a missing file is simply empty.
      try {
        text = fs.readFileSync(file, 'utf8');
      } catch (_) {
        continue;
      }
      for (const line of text.split(/\r?\n/)) {
        const entry = parseLine(line);
        if (entry) out.push(entry);
      }
    }
    return out;
  }

  function lookup(host, port, blob) {
    const name = hostName(host, port);
    const hits = readAll().filter((e) => patternsMatch(e.patterns, name));
    const presented = keyFingerprint(blob);
    const expected = hits.map((e) => keyFingerprint(e.blob));
    const base = { presented, expected };

    for (const e of hits) {
      if (e.markers.includes('@revoked') && e.blob.equals(blob)) {
        return { status: 'revoked', ...base };
      }
    }
    // The bridge cannot validate a CA signature, so a CA-backed host is
    // refused outright instead of silently falling back to trust-on-first-use.
    if (hits.some((e) => e.markers.includes('@cert-authority'))) {
      return { status: 'ca-unsupported', ...base };
    }
    // The blob embeds the key type, so an equal blob is an equal key.
    for (const e of hits) {
      if (e.blob.equals(blob)) return { status: 'match', ...base };
    }
    if (hits.length === 0) return { status: 'none', ...base };
    return { status: 'mismatch', ...base };
  }

  function remember(host, port, blob) {
    const type = keyTypeOf(blob);
    if (!type) return false;
    fs.mkdirSync(path.dirname(writePath), { recursive: true });
    fs.appendFileSync(writePath, `${hostName(host, port)} ${type} ${blob.toString('base64')}\n`, { mode: 0o600 });
    return true;
  }

  function warnOnce(key, message) {
    if (warned.has(key)) return;
    warned.add(key);
    console.error(message);
  }

  return { lookup, remember, readPaths, writePath, warnOnce };
}

// Returns { ok: true } or { ok: false, message }. Never throws: ssh2 calls
// this from inside its key-exchange packet handler, where an exception would
// escape as an opaque protocol failure instead of a readable error.
function verifyHostKey({ store, policy, host, port, blob, label, pinnedFingerprint }) {
  try {
    const presented = keyFingerprint(blob);
    const hint = (extra) =>
      `${extra} Record the expected key in known_hosts (e.g. \`ssh-keyscan -p ${port} ${host} >> ${store.writePath}\`) or set "hostKeyFingerprint" for host "${label}" to "${presented}".`;

    if (pinnedFingerprint) {
      if (normalizeFingerprint(pinnedFingerprint) === normalizeFingerprint(presented)) return { ok: true };
      return {
        ok: false,
        message: `host key mismatch for "${label}": pinned SHA256:${normalizeFingerprint(pinnedFingerprint)}, presented ${presented}. ` +
          'This can mean the host was rebuilt, or that something is impersonating it.',
      };
    }

    // Default policy: take the host key on faith and skip the trust store
    // entirely, so an unconfigured bridge does no extra work on connect.
    if (policy === 'insecure') return { ok: true };

    const result = store.lookup(host, port, blob);
    switch (result.status) {
      case 'match':
        return { ok: true };
      case 'revoked':
        return { ok: false, message: `host key for "${label}" is marked @revoked in ${store.writePath} (${presented}).` };
      case 'ca-unsupported':
        return {
          ok: false,
          message: `known host "${label}" is signed by a @cert-authority entry, which ssh-bridge does not support; ` +
            `pin the key explicitly with "hostKeyFingerprint" for host "${label}" (presented ${presented}).`,
        };
      case 'mismatch':
        return {
          ok: false,
          message: `host key mismatch for "${label}": presented ${presented}, known ${result.expected.join(', ')}. ` +
            'If the host was legitimately rebuilt, remove its line from known_hosts and reconnect.',
        };
      case 'none':
        if (policy === 'strict') {
          return { ok: false, message: hint(`host "${label}" is not in any known_hosts file and hostKeyPolicy is "strict".`) };
        }
        // tofu: first contact has nothing to check against, so trust this key
        // and require it to match from now on.
        if (!store.remember(host, port, blob)) {
          return { ok: false, message: `host "${label}": could not record the presented host key (${presented}).` };
        }
        store.warnOnce(
          `tofu:${label}`,
          `[ssh-bridge-mcp] recorded new host key for "${label}" (${presented}) in ${store.writePath}`
        );
        return { ok: true };
      default:
        return { ok: false, message: `host "${label}": unrecognized host key state` };
    }
  } catch (err) {
    return { ok: false, message: `host key verification for "${label}" failed: ${err.message}` };
  }
}

module.exports = {
  createKnownHostsStore,
  defaultKnownHostsPaths,
  keyFingerprint,
  keyTypeOf,
  normalizeFingerprint,
  hostName,
  parseLine,
  patternsMatch,
  verifyHostKey,
};
