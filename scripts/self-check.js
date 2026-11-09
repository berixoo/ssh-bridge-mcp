#!/usr/bin/env node
// Offline checks for the parts of this bridge that are easy to regress and
// impossible to notice by hand: known_hosts parsing, host key verification,
// the local path boundary, read/download bounds, and algorithm selection.
//
// No network and no SSH server are involved -- everything runs against fakes.
// Run with: npm test

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const hostkeys = require(path.join(ROOT, 'src', 'hostkeys.js'));
const paths = require(path.join(ROOT, 'src', 'paths.js'));
const {
  createBridge,
  readdirRemote,
  readFrom,
  readBinary,
  statRemote,
  connectAlgorithms,
  downloadLimit,
  makeExecCommand,
  describeSftpError,
  SHA1_REMOVALS,
  DEFAULT_MAX_DOWNLOAD,
  MAX_OUTPUT,
} = require(path.join(ROOT, 'src', 'ssh.js'));
const {
  buildCaptureScript,
  buildOptimizeScript,
  parseCaptureResult,
  looksLikeImage,
  NO_SESSION,
} = require(path.join(ROOT, 'src', 'screenshot.js'));
const { resolveHost } = require(path.join(ROOT, 'src', 'config.js'));

let pass = 0;
const failures = [];

function check(name, fn) {
  try {
    fn();
    pass++;
  } catch (err) {
    failures.push({ name, message: err.message });
    console.log(`  FAIL ${name}\n       ${err.message}`);
  }
}

async function checkAsync(name, fn) {
  try {
    await fn();
    pass++;
  } catch (err) {
    failures.push({ name, message: err.message });
    console.log(`  FAIL ${name}\n       ${err.message}`);
  }
}

function section(title) {
  console.log(`\n${title}`);
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-bridge-selfcheck-'));

// --- fixtures --------------------------------------------------------------

function blob(type, seed) {
  const t = Buffer.from(type, 'ascii');
  const key = Buffer.alloc(32, seed);
  const a = Buffer.alloc(4);
  a.writeUInt32BE(t.length);
  const b = Buffer.alloc(4);
  b.writeUInt32BE(key.length);
  return Buffer.concat([a, t, b, key]);
}
const KEY_A = blob('ssh-ed25519', 0xaa);
const KEY_B = blob('ssh-ed25519', 0xbb);
const RSA_A = blob('ssh-rsa', 0xcc);
const FP_A = hostkeys.keyFingerprint(KEY_A);

function knownHostsStore(lines) {
  const file = path.join(tmp, `kh-${crypto.randomBytes(4).toString('hex')}`);
  if (lines) fs.writeFileSync(file, lines.join('\n') + '\n');
  return hostkeys.createKnownHostsStore([file]);
}
const HOST = { host: 'dev01', port: 22, label: 'dev01' };

function fakeSftp(source, { reportedSize, readError, fstatError, maxChunk } = {}) {
  const state = { opens: 0, closes: 0 };
  return {
    state,
    open(file, flags, cb) { state.opens++; cb(null, 'handle'); },
    close(handle, cb) { state.closes++; cb(null); },
    fstat(handle, cb) {
      cb(fstatError || null, fstatError ? undefined : { size: reportedSize === undefined ? source.length : reportedSize });
    },
    read(handle, buf, offset, length, position, cb) {
      if (readError) return cb(readError);
      // maxChunk models the SFTP packet ceiling: a single read returns at most
      // this many bytes however much was asked for.
      const want = maxChunk === undefined ? length : Math.min(length, maxChunk);
      const chunk = source.subarray(position, position + want);
      chunk.copy(buf, offset);
      cb(null, chunk.length);
    },
  };
}

// A client whose handshake either succeeds or is refused, with no real socket.
function fakeClientFactory({ blob: presented = KEY_A, onConnect, sftp } = {}) {
  return () => ({
    on(ev, fn) { (this.h = this.h || {})[ev] = fn; return this; },
    connect(opts) {
      if (onConnect) onConnect(opts);
      const permitted = opts.hostVerifier ? opts.hostVerifier(presented) : undefined;
      setImmediate(() => {
        if (permitted) this.h.ready();
        else {
          this.h.error(new Error('Host denied (verification failed)'));
          this.h.close();
        }
      });
    },
    end() {},
    // Reaching exec proves the handshake was permitted.
    exec() { throw new Error('REACHED_EXEC'); },
    sftp(cb) { cb(sftp ? null : new Error('no sftp in this test'), sftp); },
  });
}

function sftpOnly(sftp) {
  return () => ({
    on(ev, fn) { (this.h = this.h || {})[ev] = fn; return this; },
    connect() { setImmediate(() => this.h.ready()); },
    end() {},
    sftp(cb) { cb(null, sftp); },
  });
}

// Just enough SFTP for start_background: write the script, then let the exec
// stub return a pid.
function sftpForTask() {
  return {
    writeFile: (f, c, cb) => cb(null),
    mkdir: (d, cb) => cb(null),
    stat: (d, cb) => cb(Object.assign(new Error('no'), { code: 2 })),
  };
}

const rootsDir = path.join(tmp, 'allowed');
const outsideDir = path.join(tmp, 'outside');
fs.mkdirSync(path.join(rootsDir, 'sub'), { recursive: true });
fs.mkdirSync(outsideDir, { recursive: true });
const configFile = path.join(tmp, 'config.json');
fs.writeFileSync(configFile, '{}');
const cfg = { localRoots: [rootsDir], hosts: {} };
const checkLocal = (localPath, conf = cfg) =>
  paths.checkLocalPath({ localPath, cfg: conf, configFile, tool: 'upload' });

const BASE_CFG = {
  default: 'dev01',
  knownHosts: [path.join(tmp, 'bridge-known-hosts')],
  localRoots: [rootsDir],
  hosts: { dev01: { host: '10.0.0.5', port: 22, user: 'u', password: 'p' } },
};
const noNet = { clientFactory: () => { throw new Error('clientFactory must not be reached'); }, configFile };

async function main() {
  section('key blobs and fingerprints');
  check('keyTypeOf reads the length-prefixed type', () =>
    assert.strictEqual(hostkeys.keyTypeOf(KEY_A), 'ssh-ed25519'));
  check('fingerprint is base64(sha256(blob)) with padding stripped', () => {
    assert.ok(FP_A.startsWith('SHA256:'));
    assert.ok(!FP_A.includes('='), 'padding must be stripped');
    assert.strictEqual(FP_A, 'SHA256:' + crypto.createHash('sha256').update(KEY_A).digest('base64').replace(/=+$/, ''));
  });
  check('keyTypeOf rejects a malformed blob', () =>
    assert.strictEqual(hostkeys.keyTypeOf(Buffer.from([0, 0, 0, 99, 1, 2])), null));

  section('known_hosts parsing and matching');
  check('plain line parses', () => {
    const e = hostkeys.parseLine(`dev01 ssh-ed25519 ${KEY_A.toString('base64')}`);
    assert.strictEqual(e.keyType, 'ssh-ed25519');
    assert.deepStrictEqual(e.patterns, ['dev01']);
  });
  check('comments and blank lines are skipped', () => {
    assert.strictEqual(hostkeys.parseLine('# nope'), null);
    assert.strictEqual(hostkeys.parseLine('   '), null);
  });
  check('markers are captured', () => {
    const e = hostkeys.parseLine(`@revoked dev01 ssh-rsa ${RSA_A.toString('base64')}`);
    assert.deepStrictEqual(e.markers, ['@revoked']);
    assert.deepStrictEqual(e.patterns, ['dev01']);
  });
  check('port 22 is plain, other ports are bracketed', () => {
    assert.strictEqual(hostkeys.hostName('10.0.0.5', 22), '10.0.0.5');
    assert.strictEqual(hostkeys.hostName('10.0.0.5', 2222), '[10.0.0.5]:2222');
  });
  check('a comma list matches either name', () => {
    assert.ok(hostkeys.patternsMatch(['a', 'b'], 'b'));
    assert.ok(!hostkeys.patternsMatch(['a', 'b'], 'c'));
  });
  check('a negation vetoes the line', () => {
    assert.ok(!hostkeys.patternsMatch(['*.lan', '!bad.lan'], 'bad.lan'));
    assert.ok(hostkeys.patternsMatch(['*.lan', '!bad.lan'], 'good.lan'));
  });
  check('glob patterns match', () => assert.ok(hostkeys.patternsMatch(['10.0.0.*'], '10.0.0.7')));
  check('a hashed entry matches', () => {
    const salt = crypto.randomBytes(8);
    const hash = crypto.createHmac('sha1', salt).update('secret.host').digest('base64').replace(/=+$/, '');
    const pattern = `|1|${salt.toString('base64')}|${hash}`;
    assert.ok(hostkeys.patternsMatch([pattern], 'secret.host'));
    assert.ok(!hostkeys.patternsMatch([pattern], 'other.host'));
  });

  section('effective defaults');
  const H = { host: 'h', port: 22, user: 'u' };
  check('hostKeyPolicy defaults to insecure', () =>
    assert.strictEqual(resolveHost({ hosts: { a: H } }, 'a').hostKeyPolicy, 'insecure'));
  check('a global hostKeyPolicy applies to every host', () =>
    assert.strictEqual(resolveHost({ hostKeyPolicy: 'tofu', hosts: { a: H } }, 'a').hostKeyPolicy, 'tofu'));
  check('a per-host hostKeyPolicy overrides the global one', () => {
    const cfgWithPolicy = { hostKeyPolicy: 'strict', hosts: { a: { ...H, hostKeyPolicy: 'tofu' } } };
    assert.strictEqual(resolveHost(cfgWithPolicy, 'a').hostKeyPolicy, 'tofu');
  });
  check('sudoPassword falls back to password (unchanged, by design)', () => {
    assert.strictEqual(resolveHost({ hosts: { a: { ...H, password: 'pw' } } }, 'a').sudoPassword, 'pw');
    assert.strictEqual(resolveHost({ hosts: { a: { ...H, password: 'pw', sudoPassword: 'sp' } } }, 'a').sudoPassword, 'sp');
  });

  section('host key verification');
  check('tofu accepts on first contact and records the key', () => {
    const store = knownHostsStore();
    assert.strictEqual(hostkeys.verifyHostKey({ ...HOST, store, policy: 'tofu', blob: KEY_A }).ok, true);
    assert.ok(fs.readFileSync(store.writePath, 'utf8').includes(`dev01 ssh-ed25519 ${KEY_A.toString('base64')}`));
  });
  check('tofu accepts the same key again', () => {
    const store = knownHostsStore([`dev01 ssh-ed25519 ${KEY_A.toString('base64')}`]);
    assert.strictEqual(hostkeys.verifyHostKey({ ...HOST, store, policy: 'tofu', blob: KEY_A }).ok, true);
  });
  check('tofu rejects a changed key and names both fingerprints', () => {
    const store = knownHostsStore([`dev01 ssh-ed25519 ${KEY_A.toString('base64')}`]);
    const v = hostkeys.verifyHostKey({ ...HOST, store, policy: 'tofu', blob: KEY_B });
    assert.strictEqual(v.ok, false);
    assert.ok(/mismatch/i.test(v.message), v.message);
    assert.ok(v.message.includes(FP_A));
    assert.ok(v.message.includes(hostkeys.keyFingerprint(KEY_B)));
  });
  check('strict refuses an unknown host and writes nothing', () => {
    const store = knownHostsStore();
    const v = hostkeys.verifyHostKey({ ...HOST, store, policy: 'strict', blob: KEY_A });
    assert.strictEqual(v.ok, false);
    assert.ok(/not in any known_hosts/i.test(v.message), v.message);
    assert.ok(!fs.existsSync(store.writePath));
  });
  check('insecure accepts an unknown host and writes nothing', () => {
    const store = knownHostsStore();
    assert.strictEqual(hostkeys.verifyHostKey({ ...HOST, store, policy: 'insecure', blob: KEY_A }).ok, true);
    assert.ok(!fs.existsSync(store.writePath));
  });
  check('port-aware entries do not leak across ports', () => {
    const store = knownHostsStore([`[dev01]:2222 ssh-ed25519 ${KEY_A.toString('base64')}`]);
    assert.strictEqual(hostkeys.verifyHostKey({ ...HOST, store, policy: 'strict', blob: KEY_A }).ok, false);
    assert.strictEqual(hostkeys.verifyHostKey({ ...HOST, port: 2222, store, policy: 'strict', blob: KEY_A }).ok, true);
  });
  check('a pinned fingerprint wins over known_hosts', () => {
    const store = knownHostsStore([`dev01 ssh-ed25519 ${KEY_B.toString('base64')}`]);
    assert.strictEqual(
      hostkeys.verifyHostKey({ ...HOST, store, policy: 'tofu', blob: KEY_A, pinnedFingerprint: FP_A }).ok,
      true
    );
  });
  check('a pinned fingerprint tolerates the SHA256: prefix', () => {
    const store = knownHostsStore();
    assert.strictEqual(
      hostkeys.verifyHostKey({ ...HOST, store, policy: 'strict', blob: KEY_A, pinnedFingerprint: FP_A.slice(7) }).ok,
      true
    );
  });
  check('a matching @revoked key is refused', () => {
    const store = knownHostsStore([`@revoked dev01 ssh-ed25519 ${KEY_A.toString('base64')}`]);
    const v = hostkeys.verifyHostKey({ ...HOST, store, policy: 'tofu', blob: KEY_A });
    assert.strictEqual(v.ok, false);
    assert.ok(/revoked/i.test(v.message), v.message);
  });
  check('@cert-authority is refused, not silently downgraded to tofu', () => {
    const store = knownHostsStore([`@cert-authority dev01 ssh-ed25519 ${KEY_A.toString('base64')}`]);
    const v = hostkeys.verifyHostKey({ ...HOST, store, policy: 'tofu', blob: KEY_A });
    assert.strictEqual(v.ok, false);
    assert.ok(/cert-authority/i.test(v.message), v.message);
  });
  check('a hashed known_hosts written by OpenSSH still matches', () => {
    const salt = crypto.randomBytes(8);
    const hash = crypto.createHmac('sha1', salt).update('dev01').digest('base64').replace(/=+$/, '');
    const store = knownHostsStore([`|1|${salt.toString('base64')}|${hash} ssh-ed25519 ${KEY_A.toString('base64')}`]);
    assert.strictEqual(hostkeys.verifyHostKey({ ...HOST, store, policy: 'strict', blob: KEY_A }).ok, true);
  });
  check('verifyHostKey never throws on a bogus blob', () => {
    const store = knownHostsStore();
    assert.strictEqual(typeof hostkeys.verifyHostKey({ ...HOST, store, policy: 'tofu', blob: Buffer.from('x') }).ok, 'boolean');
  });

  section('local path boundary');
  check('a path inside a root resolves', () => {
    assert.strictEqual(
      checkLocal(path.join(rootsDir, 'sub', 'file.txt')),
      path.join(fs.realpathSync(path.join(rootsDir, 'sub')), 'file.txt')
    );
  });
  check('the root itself resolves', () => assert.strictEqual(checkLocal(rootsDir), fs.realpathSync(rootsDir)));
  check('a relative root resolves against the config file, not the cwd', () => {
    const conf = { hosts: {}, localRoots: ['allowed'] };
    assert.strictEqual(checkLocal(rootsDir, conf), fs.realpathSync(rootsDir));
    assert.throws(() => checkLocal(rootsDir, { hosts: {}, localRoots: ['nope'] }), /outside the configured localRoots/);
  });
  check('no localRoots means unrestricted (the default)', () =>
    assert.strictEqual(checkLocal(path.join(outsideDir, 'a.txt'), { hosts: {} }), path.join(fs.realpathSync(outsideDir), 'a.txt')));
  check('an absolute path outside every root is refused', () =>
    assert.throws(() => checkLocal(path.join(outsideDir, 'secret.txt')), /outside the configured localRoots/));
  check('.. traversal out of a root is refused', () =>
    assert.throws(() => checkLocal(path.join(rootsDir, '..', 'outside', 'secret.txt')), /outside the configured localRoots/));
  check('a sibling directory sharing a name prefix is refused', () => {
    const sibling = path.join(tmp, 'allowed-evil');
    fs.mkdirSync(sibling, { recursive: true });
    assert.throws(() => checkLocal(path.join(sibling, 'x')), /outside the configured localRoots/);
  });
  check('the config file is refused with no localRoots', () =>
    assert.throws(() => checkLocal(configFile, { hosts: {} }), /configuration file/));
  check('the config file is refused with localRoots set', () =>
    assert.throws(() => checkLocal(configFile), /configuration file/));
  check('Windows path casing does not defeat the root check', () => {
    if (process.platform !== 'win32') return;
    assert.ok(checkLocal(rootsDir.toUpperCase() + path.sep + 'sub' + path.sep + 'f.txt'));
  });
  check('a symlink pointing outside the root is refused', () => {
    const link = path.join(rootsDir, 'escape');
    try {
      fs.symlinkSync(outsideDir, link, 'junction');
    } catch (err) {
      console.log(`       (skipped: cannot create a symlink here: ${err.code})`);
      return;
    }
    assert.throws(() => checkLocal(path.join(link, 'secret.txt')), /outside the configured localRoots/);
  });

  section('algorithm selection');
  check('ssh-rsa and the sha1 MACs are removed from the default offer', () => {
    const a = connectAlgorithms({});
    assert.deepStrictEqual(a, SHA1_REMOVALS);
    assert.deepStrictEqual(a.serverHostKey.remove, ['ssh-rsa']);
    assert.ok(a.hmac.remove.includes('hmac-sha1'));
    assert.ok(a.hmac.remove.includes('hmac-sha1-etm@openssh.com'));
  });
  check('sha2 host keys and MACs are left alone', () => {
    const a = connectAlgorithms({});
    assert.ok(!a.serverHostKey.remove.includes('rsa-sha2-512'));
    assert.ok(!a.serverHostKey.remove.includes('ssh-ed25519'));
    assert.ok(!a.hmac.remove.includes('hmac-sha2-256'));
  });
  check('allowLegacyAlgorithms restores ssh2 defaults', () =>
    assert.strictEqual(connectAlgorithms({ allowLegacyAlgorithms: true }), undefined));
  check('an exact array replaces the removal for that group only', () => {
    const a = connectAlgorithms({ algorithms: { serverHostKey: ['ssh-ed25519'] } });
    assert.deepStrictEqual(a.serverHostKey, ['ssh-ed25519']);
    assert.deepStrictEqual(a.hmac, SHA1_REMOVALS.hmac, 'other groups keep the removal');
  });
  check('an operation object is merged so the removal survives', () => {
    const a = connectAlgorithms({ algorithms: { hmac: { append: ['hmac-md5'] } } });
    assert.ok(a.hmac.remove.includes('hmac-sha1'));
    assert.deepStrictEqual(a.hmac.append, ['hmac-md5']);
  });
  check('allowLegacyAlgorithms still honours an explicit list', () => {
    const a = connectAlgorithms({ allowLegacyAlgorithms: true, algorithms: { hmac: ['hmac-sha1'] } });
    assert.deepStrictEqual(a, { hmac: ['hmac-sha1'] });
  });

  section('download limit');
  check('the default limit is 2 GiB', () =>
    assert.strictEqual(downloadLimit({}), 2 * 1024 * 1024 * 1024));
  check('maxDownloadBytes overrides it, and 0 means unlimited', () => {
    assert.strictEqual(downloadLimit({ maxDownloadBytes: 1024 }), 1024);
    assert.strictEqual(downloadLimit({ maxDownloadBytes: 0 }), 0);
  });

  section('readFrom bounds');
  await checkAsync('a small file comes back whole', async () => {
    const r = await readFrom(fakeSftp(Buffer.from('hello world')), '/log', 0);
    assert.strictEqual(r.content, 'hello world');
    assert.strictEqual(r.size, 11);
    assert.strictEqual(r.truncated, false);
    assert.strictEqual(r.error, null);
  });
  await checkAsync('a large file is capped at MAX_OUTPUT', async () => {
    const r = await readFrom(fakeSftp(Buffer.alloc(MAX_OUTPUT * 2 + 17, 0x41)), '/log', 0);
    assert.strictEqual(Buffer.byteLength(r.content), MAX_OUTPUT);
    assert.strictEqual(r.size, MAX_OUTPUT);
    assert.strictEqual(r.truncated, true);
  });
  await checkAsync('the remainder arrives on the next poll with no skipped bytes', async () => {
    const src = Buffer.alloc(MAX_OUTPUT + 100, 0);
    for (let i = 0; i < src.length; i++) src[i] = 0x41 + (i % 26);
    let offset = 0;
    let out = Buffer.alloc(0);
    for (let i = 0; i < 5; i++) {
      const r = await readFrom(fakeSftp(src), '/log', offset);
      out = Buffer.concat([out, Buffer.from(r.content, 'utf8')]);
      offset = r.size;
      if (!r.truncated) break;
    }
    assert.ok(out.equals(src), `reassembled ${out.length} of ${src.length} bytes`);
  });
  await checkAsync('an offset past EOF is treated as a rotated file and restarts', async () => {
    const r = await readFrom(fakeSftp(Buffer.from('abc')), '/log', 99);
    assert.strictEqual(r.content, 'abc');
    assert.strictEqual(r.size, 3);
  });
  await checkAsync('a lying fstat cannot trigger a huge allocation', async () => {
    const r = await readFrom(fakeSftp(Buffer.from('tiny'), { reportedSize: 8 * 1024 * 1024 * 1024 }), '/log', 0);
    assert.strictEqual(r.content, 'tiny');
    assert.strictEqual(r.truncated, true);
  });
  await checkAsync('a read error is reported, not returned as empty success', async () => {
    const r = await readFrom(fakeSftp(Buffer.from('x'), { readError: new Error('permission denied') }), '/log', 0);
    assert.ok(r.error);
    assert.strictEqual(r.content, '');
  });
  await checkAsync('a missing file reports ENOENT as an error', async () => {
    const r = await readFrom({ open: (f, fl, cb) => cb(Object.assign(new Error('No such file'), { code: 2 })) }, '/log', 0);
    assert.strictEqual(r.error.code, 2);
  });
  await checkAsync('the handle is closed on every path', async () => {
    const cases = [
      ['success', fakeSftp(Buffer.from('abc')), 0],
      ['empty read at EOF', fakeSftp(Buffer.from('abc')), 3],
      ['rotated restart', fakeSftp(Buffer.from('abc')), 99],
      ['read error', fakeSftp(Buffer.from('abc'), { readError: new Error('boom') }), 0],
      ['fstat error', fakeSftp(Buffer.from('abc'), { fstatError: new Error('bad fstat') }), 0],
    ];
    for (const [label, sftp, offset] of cases) {
      await readFrom(sftp, '/f', offset);
      assert.strictEqual(sftp.state.opens, 1, `${label}: expected one open`);
      assert.strictEqual(sftp.state.closes, 1, `${label}: handle left open`);
    }
  });

  section('bridge wiring');
  function downloadSftp({ size, written, statError, getError }) {
    const calls = [];
    return {
      calls,
      stat(file, cb) { cb(statError || null, statError ? undefined : { size }); },
      fastGet(remote, local, opts, cb) {
        calls.push({ remote, local, opts });
        if (getError) return cb(getError);
        fs.mkdirSync(path.dirname(local), { recursive: true });
        fs.writeFileSync(local, Buffer.alloc(written === undefined ? size : written, 0x41));
        cb(null);
      },
    };
  }
  function bridgeWith(clientFactory, conf = BASE_CFG) {
    return createBridge(conf, { clientFactory, configFile });
  }
  const runCmd = (conf, factory) => bridgeWith(factory, conf).runCommand(undefined, { command: 'true' });

  await checkAsync('connect() receives the algorithm list and a hostVerifier', async () => {
    const seen = [];
    await runCmd(BASE_CFG, fakeClientFactory({ onConnect: (o) => seen.push(o) })).catch(() => {});
    assert.strictEqual(seen.length, 1);
    assert.strictEqual(typeof seen[0].hostVerifier, 'function');
    assert.deepStrictEqual(seen[0].algorithms, SHA1_REMOVALS);
    assert.strictEqual(seen[0].password, 'p', 'password still passed through');
  });
  await checkAsync('allowLegacyAlgorithms leaves the offer untouched', async () => {
    const seen = [];
    const conf = { ...BASE_CFG, allowLegacyAlgorithms: true };
    await runCmd(conf, fakeClientFactory({ onConnect: (o) => seen.push(o) })).catch(() => {});
    assert.strictEqual(seen[0].algorithms, undefined);
  });
  await checkAsync('the default policy writes no trust store', async () => {
    await runCmd(BASE_CFG, fakeClientFactory()).catch(() => {});
    assert.ok(!fs.existsSync(BASE_CFG.knownHosts[0]));
  });
  await checkAsync('the default policy lets a connect through', async () => {
    await assert.rejects(() => runCmd(BASE_CFG, fakeClientFactory()), /REACHED_EXEC/);
  });
  await checkAsync('tofu records the key on a real connect', async () => {
    await runCmd({ ...BASE_CFG, hostKeyPolicy: 'tofu' }, fakeClientFactory()).catch(() => {});
    assert.ok(fs.readFileSync(BASE_CFG.knownHosts[0], 'utf8').includes(`10.0.0.5 ssh-ed25519 ${KEY_A.toString('base64')}`));
  });
  await checkAsync('strict surfaces our message, not ssh2 generic text', async () => {
    const conf = { ...BASE_CFG, hostKeyPolicy: 'strict', knownHosts: [path.join(tmp, 'empty-kh')] };
    await assert.rejects(() => runCmd(conf, fakeClientFactory()), (err) => {
      assert.ok(/not in any known_hosts/i.test(err.message), err.message);
      assert.ok(!/Host denied \(verification failed\)/.test(err.message));
      return true;
    });
  });
  await checkAsync('a changed key is refused under tofu', async () => {
    const store = path.join(tmp, 'changed-kh');
    fs.writeFileSync(store, `10.0.0.5 ssh-ed25519 ${KEY_B.toString('base64')}\n`);
    await assert.rejects(() => runCmd({ ...BASE_CFG, hostKeyPolicy: 'tofu', knownHosts: [store] }, fakeClientFactory()), /mismatch/i);
  });
  await checkAsync('a changed key is accepted under the default policy', async () => {
    const store = path.join(tmp, 'changed-kh2');
    fs.writeFileSync(store, `10.0.0.5 ssh-ed25519 ${KEY_B.toString('base64')}\n`);
    await assert.rejects(() => runCmd({ ...BASE_CFG, knownHosts: [store] }, fakeClientFactory()), /REACHED_EXEC/);
  });

  section('read_file size limit');
  await checkAsync('read_file returns a small remote file', async () => {
    const b = bridgeWith(sftpOnly(fakeSftp(Buffer.from('contents'))));
    assert.strictEqual((await b.readFile('dev01', '/small.txt')).content, 'contents');
  });
  await checkAsync('read_file refuses a file over the limit', async () => {
    const b = bridgeWith(sftpOnly(fakeSftp(Buffer.alloc(MAX_OUTPUT + 1, 0x41))));
    await assert.rejects(() => b.readFile('dev01', '/big.log'), /not read completely/);
  });
  await checkAsync('read_file surfaces a missing file as an error', async () => {
    const sftp = { open: (f, fl, cb) => cb(Object.assign(new Error('No such file'), { code: 2 })) };
    await assert.rejects(() => bridgeWith(sftpOnly(sftp)).readFile('dev01', '/nope'), /No such file/);
  });

  section('download bounds and integrity');
  await checkAsync('statRemote surfaces a stat failure', async () => {
    const err = Object.assign(new Error('No such file'), { code: 2 });
    await assert.rejects(() => statRemote({ stat: (f, cb) => cb(err) }, '/x'), /No such file/);
  });
  await checkAsync('a file under the limit downloads', async () => {
    const sftp = downloadSftp({ size: 2048 });
    const dest = path.join(rootsDir, 'ok.bin');
    await bridgeWith(sftpOnly(sftp)).download('dev01', '/remote.bin', dest);
    assert.strictEqual(fs.statSync(dest).size, 2048);
  });
  await checkAsync('the checked size is passed to fastGet as the hard ceiling', async () => {
    const sftp = downloadSftp({ size: 4096 });
    await bridgeWith(sftpOnly(sftp)).download('dev01', '/remote.bin', path.join(rootsDir, 'ceil.bin'));
    assert.strictEqual(sftp.calls.length, 1);
    assert.strictEqual(sftp.calls[0].opts.fileSize, 4096);
  });
  await checkAsync('a file over maxDownloadBytes is refused before any transfer', async () => {
    const sftp = downloadSftp({ size: 5000 });
    const conf = { ...BASE_CFG, maxDownloadBytes: 4096 };
    await assert.rejects(
      () => bridgeWith(sftpOnly(sftp), conf).download('dev01', '/big.bin', path.join(rootsDir, 'big.bin')),
      /exceeds maxDownloadBytes/
    );
    assert.strictEqual(sftp.calls.length, 0, 'fastGet must never be reached');
    assert.ok(!fs.existsSync(path.join(rootsDir, 'big.bin')));
  });
  await checkAsync('maxDownloadBytes: 0 disables the check', async () => {
    const sftp = downloadSftp({ size: 5000 });
    const conf = { ...BASE_CFG, maxDownloadBytes: 0 };
    await bridgeWith(sftpOnly(sftp), conf).download('dev01', '/big.bin', path.join(rootsDir, 'unlimited.bin'));
    assert.strictEqual(sftp.calls.length, 1);
  });
  await checkAsync('a short write is reported instead of passing as success', async () => {
    const sftp = downloadSftp({ size: 4096, written: 1000 });
    await assert.rejects(
      () => bridgeWith(sftpOnly(sftp)).download('dev01', '/short.bin', path.join(rootsDir, 'short.bin')),
      /wrote 1000 of 4096 bytes/
    );
  });
  await checkAsync('a remote that lies about the size cannot exceed the ceiling', async () => {
    // stat reports 100 bytes, so that is what fastGet is bounded by -- the
    // transfer can never grow to what the remote actually holds.
    const sftp = downloadSftp({ size: 100 });
    await bridgeWith(sftpOnly(sftp)).download('dev01', '/liar.bin', path.join(rootsDir, 'liar.bin'));
    assert.strictEqual(sftp.calls[0].opts.fileSize, 100);
  });

  section('upload and download policy');
  await checkAsync('upload refuses an out-of-root local path', () =>
    assert.rejects(() => createBridge(BASE_CFG, noNet).upload('dev01', path.join(outsideDir, 's.txt'), '/tmp/x'), /outside the configured localRoots/));
  await checkAsync('upload refuses the config file with localRoots unset', () =>
    assert.rejects(() => createBridge({ ...BASE_CFG, localRoots: undefined }, noNet).upload('dev01', configFile, '/tmp/x'), /configuration file/));
  await checkAsync('with no localRoots an outside path reaches the network layer', () =>
    assert.rejects(() => createBridge({ ...BASE_CFG, localRoots: undefined }, noNet).upload('dev01', path.join(outsideDir, 'f.txt'), '/tmp/x'), /must not be reached/));
  await checkAsync('download refuses an out-of-root local path', () =>
    assert.rejects(() => createBridge(BASE_CFG, noNet).download('dev01', '/etc/shadow', path.join(outsideDir, 'shadow')), /outside the configured localRoots/));

  section('screenshot helpers');
  check('capture script discovers the session through logind, not $DISPLAY', () => {
    const s = buildCaptureScript();
    assert.ok(s.includes('loginctl list-sessions'));
    assert.ok(s.includes('show-session'), 'must read Type/Display from logind');
    assert.ok(/wayland\|x11/.test(s), 'must skip tty sessions when choosing the seat session');
  });
  check('every capture attempt is bounded by timeout', () => {
    const s = buildCaptureScript();
    assert.ok(s.includes('timeout 20'), 'gnome-screenshot blocks forever on its X11 fallback');
    assert.strictEqual((s.match(/timeout 20 "\$@"/g) || []).length, 1);
  });
  check('GNOME gets gnome-screenshot over Xwayland with the mutter auth file', () => {
    const s = buildCaptureScript();
    assert.ok(s.includes('.mutter-Xwaylandauth.'));
    assert.ok(/gnome-screenshot-xwayland/.test(s));
    assert.ok(/DISPLAY=:0 XAUTHORITY=/.test(s));
  });
  check('wayland chain also covers wlroots via grim', () => {
    const s = buildCaptureScript();
    assert.ok(s.includes('grim'));
    assert.ok(s.includes('spectacle'));
  });
  check('no screenshot means exit 3, not a silent empty file', () => {
    assert.strictEqual(NO_SESSION, 3);
    assert.ok(buildCaptureScript().includes('exit 3'), 'script must exit 3 for no session');
  });
  check('capture script survives systemd < 230 and an unset XDG_SESSION_TYPE', () => {
    const s = buildCaptureScript();
    assert.ok(!/^set -u$/m.test(s), 'set -u kills the script on Ubuntu 16.04, where XDG_SESSION_TYPE is unset');
    assert.ok(s.includes('show_prop'), 'session properties need a prefix-stripping fallback for loginctl --value');
  });
  check('parses a successful capture', () => {
    const r = parseCaptureResult('noise\nRESULT|ok|gnome-screenshot-xwayland|wayland|\n');
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.tool, 'gnome-screenshot-xwayland');
    assert.strictEqual(r.sessionType, 'wayland');
  });
  check('parses a no-session result into an actionable message', () => {
    const r = parseCaptureResult('RESULT|nosession|||\n');
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.noSession, true);
    assert.ok(/no graphical session/i.test(r.error));
  });
  check('a failed capture lists what was tried', () => {
    const r = parseCaptureResult('RESULT|fail||wayland||grim; imagemagick; ');
    assert.strictEqual(r.ok, false);
    assert.ok(/tried: grim; imagemagick/.test(r.error), r.error);
    assert.ok(/gnome-screenshot/.test(r.error), 'should suggest the fix');
  });
  check('a missing result line is an error, not success', () => {
    assert.strictEqual(parseCaptureResult('').ok, false);
    assert.strictEqual(parseCaptureResult('garbage').ok, false);
  });
  check('looksLikeImage accepts real image magic and rejects junk', () => {
    const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(100)]);
    const jpeg = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(100)]);
    assert.ok(looksLikeImage(png));
    assert.ok(looksLikeImage(jpeg));
    assert.ok(!looksLikeImage(Buffer.alloc(200)), 'an all-zero capture is not an image');
    assert.ok(!looksLikeImage(Buffer.from('<html>error</html>'.padEnd(200, ' '))));
    assert.ok(!looksLikeImage(Buffer.alloc(10)), 'too small to be an image');
  });
  check('optimize script leaves the capture alone when ImageMagick is missing', () => {
    const s = buildOptimizeScript();
    assert.ok(s.includes('command -v convert'));
    assert.ok(s.includes('echo "ORIGINAL"'), 'must fall back, not fail');
  });

  section('command building');
  check('pipefail is opt-in and wraps the command before env/sudo', () => {
    assert.ok(!makeExecCommand({ command: 'cat /etc/shadow | head -1' }).includes('pipefail'));
    const strict = makeExecCommand({ command: 'cat /etc/shadow | head -1', pipefail: true });
    assert.ok(strict.startsWith('set -o pipefail; '), strict);
  });
  check('env exports survive sudo wrapping', () => {
    const c = makeExecCommand({ command: 'echo $FOO', sudo: true, env: { FOO: 'bar' } });
    // The export is inside the quoted sh -c payload, so its quotes are escaped.
    assert.ok(c.includes('export FOO='), c);
    assert.ok(c.includes('bar'), c);
    assert.ok(c.startsWith("sudo -S -p '' sh -c"), c);
  });
  check('cwd is applied outside the sudo wrapper', () => {
    const c = makeExecCommand({ command: 'id', sudo: true, cwd: '/etc' });
    assert.ok(c.startsWith("cd '/etc' && sudo"), c);
  });

  section('readBinary (image transfer)');
  await checkAsync('returns raw bytes without utf8 mangling', async () => {
    const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from([0x00, 0xff, 0x80, 0x7f])]);
    const got = await readBinary(fakeSftp(png), '/shot.png');
    assert.ok(got.equals(png), 'binary bytes must round-trip exactly');
  });
  await checkAsync('refuses an oversized binary read', async () => {
    const sftp = fakeSftp(Buffer.alloc(16), { reportedSize: MAX_OUTPUT * 4 + 1 });
    await assert.rejects(() => readBinary(sftp, '/huge.png'), /exceeds the binary read limit/);
  });
  await checkAsync('reassembles a file larger than one SFTP packet', async () => {
    // Screenshots are routinely >64 KiB; one read returns one packet and
    // reports the short count as success, which used to end the transfer early
    // and strip the JPEG EOI marker.
    const big = Buffer.alloc(200 * 1024);
    for (let i = 0; i < big.length; i++) big[i] = i & 0xff;
    const got = await readBinary(fakeSftp(big, { maxChunk: 32768 }), '/big.png');
    assert.strictEqual(got.length, big.length, 'a short read must not end the transfer early');
    assert.ok(got.equals(big), 'bytes past the first packet must survive');
  });

  section('file tools');
  await checkAsync('listDir maps attrs and sorts directories first', async () => {
    const sftp = {
      readdir(dir, cb) {
        cb(null, [
          { filename: 'z.txt', attrs: { mode: 0o100644, size: 3, mtime: 1700000000 } },
          { filename: 'a', attrs: { mode: 0o040755, size: 4096, mtime: 1700000000 } },
          { filename: '.', attrs: {} },
          { filename: '..', attrs: {} },
        ]);
      },
    };
    const r = await bridgeWith(sftpOnly(sftp)).listDir('dev01', '/x');
    assert.strictEqual(r.count, 2, 'dot entries are filtered');
    assert.strictEqual(r.entries[0].name, 'a');
    assert.strictEqual(r.entries[0].type, 'dir');
    assert.strictEqual(r.entries[1].type, 'file');
    assert.ok(r.entries[1].mtime.endsWith('Z'));
  });

  function execStub({ code, stdout = '' }) {
    return () => ({
      on(ev, fn) { (this.h = this.h || {})[ev] = fn; return this; },
      connect() { setImmediate(() => this.h.ready()); },
      end() {},
      exec(cmd, opts, cb) {
        execStub.last = cmd;
        const { EventEmitter } = require('events');
        const ch = new EventEmitter();
        ch.stdin = { write: (d, f) => f && f(), end() {} };
        ch.stderr = new EventEmitter();
        cb(null, ch);
        setImmediate(() => {
          if (stdout) ch.emit('data', Buffer.from(stdout));
          ch.emit('exit', code);
          ch.emit('close', code);
        });
        return ch;
      },
    });
  }

  await checkAsync('searchFiles treats "no matches" as an empty result, not an error', async () => {
    const b = createBridge(BASE_CFG, { clientFactory: execStub({ code: 1 }), configFile });
    const r = await b.searchFiles('dev01', { pattern: 'nothing', path: '/x' });
    assert.strictEqual(r.count, 0);
    assert.deepStrictEqual(r.matches, []);
  });
  await checkAsync('searchFiles quotes the pattern so it cannot become shell syntax', async () => {
    const b = createBridge(BASE_CFG, { clientFactory: execStub({ code: 0, stdout: '/a.txt:3:hit\n' }), configFile });
    const r = await b.searchFiles('dev01', { pattern: "a'; rm -rf /", path: '/x' });
    // Inside the outer bash -c quoting the payload is escaped; what matters is
    // that the raw `; rm -rf /` never appears unquoted as shell syntax.
    const cmd = execStub.last;
    assert.ok(!/ ;\s*rm -rf \/ /.test(cmd), `pattern leaked as syntax: ${cmd}`);
    assert.ok(cmd.includes('rm -rf /'), 'pattern text should still be passed through');
    assert.strictEqual(r.count, 1);
    assert.strictEqual(r.matches[0].file, '/a.txt');
    assert.strictEqual(r.matches[0].line, 3);
  });
  await checkAsync('searchFiles caps results at maxResults', async () => {
    const many = Array.from({ length: 50 }, (_, i) => `/f:${i + 1}:x`).join('\n') + '\n';
    const b = createBridge(BASE_CFG, { clientFactory: execStub({ code: 0, stdout: many }), configFile });
    const r = await b.searchFiles('dev01', { pattern: 'x', path: '/', maxResults: 5 });
    assert.strictEqual(r.matches.length, 5);
    assert.strictEqual(r.truncated, true);
  });

  section('SFTP error messages are actionable (#4)');
  check('numeric status codes map to names, not "Failure"', () => {
    assert.strictEqual(describeSftpError({ code: 2, message: 'No such file' }), 'NO_SUCH_FILE (No such file)');
    assert.strictEqual(describeSftpError({ code: 3, message: 'Permission denied' }), 'PERMISSION_DENIED (Permission denied)');
    assert.strictEqual(describeSftpError({ code: 4, message: 'Failure' }), 'FAILURE (Failure)');
    assert.strictEqual(describeSftpError({ code: 8, message: 'Operation unsupported' }), 'OP_UNSUPPORTED (Operation unsupported)');
  });
  check('a bare status with no message still names the code', () => {
    assert.strictEqual(describeSftpError({ code: 4 }), 'FAILURE');
  });
  check('an error without a code passes its message through', () => {
    assert.strictEqual(describeSftpError(new Error('boom')), 'boom');
    assert.strictEqual(describeSftpError(null), 'unknown error');
  });

  section('background task id key (#3)');
  await checkAsync('start_background returns both task_id and taskId', async () => {
    const bridge = createBridge(BASE_CFG, {
      clientFactory: () => ({
        on(ev, fn) { (this.h = this.h || {})[ev] = fn; return this; },
        connect() { setImmediate(() => this.h.ready()); },
        end() {},
        sftp(cb) { cb(null, sftpForTask()); },
        exec(cmd, opts, cb) {
          const { EventEmitter } = require('events');
          const ch = new EventEmitter();
          ch.stdin = { write: (d, f) => f && f(), end() {} };
          ch.stderr = new EventEmitter();
          cb(null, ch);
          // First exec launches the job, second reads the pid file.
          const out = /cat /.test(cmd) ? '4242\n' : '';
          setImmediate(() => {
            if (out) ch.emit('data', Buffer.from(out));
            ch.emit('exit', 0);
            ch.emit('close', 0);
          });
          return ch;
        },
      }),
      configFile,
    });
    const r = await bridge.startBackground('dev01', { command: 'sleep 1', cwd: '/tmp' });
    assert.ok(/^[0-9a-f]+$/.test(r.task_id), 'task_id must be present');
    assert.strictEqual(r.taskId, r.task_id, 'taskId kept for compatibility');
    assert.ok(/^\d+$/.test(r.pid));
  });

  section('error codes survive the wrappers (#4)');
  await checkAsync('readdirRemote keeps the numeric code on the thrown error', async () => {
    const sftp = { readdir: (d, cb) => cb(Object.assign(new Error('No such file'), { code: 2 })) };
    await assert.rejects(() => readdirRemote(sftp, '/x'), (err) => {
      assert.strictEqual(err.code, 2, 'code must survive, callers branch on it');
      assert.ok(/NO_SUCH_FILE/.test(err.message), err.message);
      return true;
    });
  });
  await checkAsync('list_dir on a file says NOT_A_DIRECTORY, not "No such file"', async () => {
    const sftp = {
      readdir: (d, cb) => cb(Object.assign(new Error('No such file'), { code: 2 })),
      stat: (d, cb) => cb(null, { mode: 0o100644 }),
    };
    await assert.rejects(() => bridgeWith(sftpOnly(sftp)).listDir('dev01', '/etc/hostname'), /NOT_A_DIRECTORY/);
  });
  await checkAsync('list_dir on a genuinely missing path still says NO_SUCH_FILE', async () => {
    const sftp = {
      readdir: (d, cb) => cb(Object.assign(new Error('No such file'), { code: 2 })),
      stat: (d, cb) => cb(Object.assign(new Error('No such file'), { code: 2 })),
    };
    await assert.rejects(() => bridgeWith(sftpOnly(sftp)).listDir('dev01', '/nope'), /NO_SUCH_FILE/);
  });
  await checkAsync('read_file on a directory says IS_A_DIRECTORY', async () => {
    const sftp = {
      open: (f, fl, cb) => cb(Object.assign(new Error('Failure'), { code: 4 })),
      stat: (f, cb) => cb(null, { mode: 0o040755 }),
    };
    await assert.rejects(() => bridgeWith(sftpOnly(sftp)).readFile('dev01', '/tmp'), /IS_A_DIRECTORY/);
  });
  await checkAsync('delete of a non-empty dir suggests recursive', async () => {
    const sftp = {
      lstat: (f, cb) => cb(null, { mode: 0o040755 }),
      rmdir: (d, cb) => cb(Object.assign(new Error('Failure'), { code: 4 })),
    };
    await assert.rejects(() => bridgeWith(sftpOnly(sftp)).deletePath('dev01', '/tmp/x'), /DIRECTORY_NOT_EMPTY.*recursive/);
  });
  await checkAsync('delete unlinks a symlink instead of touching its target', async () => {
    // lstat reports a link; stat would have reported the target directory and
    // sent the call down the rmdir path, failing with "No such file".
    const sftp = {
      lstat: (f, cb) => cb(null, { mode: 0o120777 }),
      unlink: (f, cb) => { sftp.unlinked = f; cb(null); },
      rmdir: () => { throw new Error('must not rmdir a symlink target'); },
    };
    const r = await bridgeWith(sftpOnly(sftp)).deletePath('dev01', '/tmp/link-dir');
    assert.strictEqual(r.removed, 'link');
    assert.strictEqual(sftp.unlinked, '/tmp/link-dir');
  });

  section('search_files error reporting (#5)');
  await checkAsync('a missing path is a tool error, not an empty result', async () => {
    const b = createBridge(BASE_CFG, {
      clientFactory: () => ({
        on(ev, fn) { (this.h = this.h || {})[ev] = fn; return this; },
        connect() { setImmediate(() => this.h.ready()); },
        end() {},
        exec(cmd, opts, cb) {
          const { EventEmitter } = require('events');
          const ch = new EventEmitter();
          ch.stdin = { write: (d, f) => f && f(), end() {} };
          ch.stderr = new EventEmitter();
          cb(null, ch);
          const isProbe = /test -e/.test(cmd);
          setImmediate(() => {
            if (isProbe) ch.emit('data', Buffer.from('missing\n'));
            ch.emit('exit', 2);
            ch.emit('close', 2);
          });
          return ch;
        },
      }),
      configFile,
    });
    await assert.rejects(() => b.searchFiles('dev01', { pattern: 'x', path: '/nonexistent' }), /path does not exist/);
  });
  await checkAsync('the localized grep message never reaches the caller', async () => {
    const b = createBridge(BASE_CFG, {
      clientFactory: () => ({
        on(ev, fn) { (this.h = this.h || {})[ev] = fn; return this; },
        connect() { setImmediate(() => this.h.ready()); },
        end() {},
        exec(cmd, opts, cb) {
          const { EventEmitter } = require('events');
          const ch = new EventEmitter();
          ch.stdin = { write: (d, f) => f && f(), end() {} };
          ch.stderr = new EventEmitter();
          cb(null, ch);
          const isProbe = /test -e/.test(cmd);
          setImmediate(() => {
            if (isProbe) ch.emit('data', Buffer.from('missing\n'));
            // Simulate a zh_CN host.
            else ch.stderr.emit('data', Buffer.from('grep: /nonexistent: 没有那个文件或目录\n'));
            ch.emit('exit', 2);
            ch.emit('close', 2);
          });
          return ch;
        },
      }),
      configFile,
    });
    await assert.rejects(() => b.searchFiles('dev01', { pattern: 'x', path: '/nonexistent' }), (err) => {
      assert.ok(!/没有那个文件/.test(err.message), `localized text leaked: ${err.message}`);
      return true;
    });
  });

  section('channel concurrency (sshd MaxSessions)');
  await checkAsync('channel opens never exceed maxConcurrentChannels', async () => {
    let inFlight = 0;
    let peak = 0;
    const b = createBridge({ ...BASE_CFG, maxConcurrentChannels: 3 }, {
      clientFactory: () => ({
        on(ev, fn) { (this.h = this.h || {})[ev] = fn; return this; },
        connect() { setImmediate(() => this.h.ready()); },
        end() {},
        exec(cmd, opts, cb) {
          inFlight++;
          peak = Math.max(peak, inFlight);
          const { EventEmitter } = require('events');
          const ch = new EventEmitter();
          ch.stdin = { write: (d, f) => f && f(), end() {} };
          ch.stderr = new EventEmitter();
          cb(null, ch);
          setTimeout(() => {
            inFlight--;
            ch.emit('exit', 0);
            ch.emit('close', 0);
          }, 5);
          return ch;
        },
      }),
      configFile,
    });
    await Promise.all(Array.from({ length: 12 }, () => b.runCommand('dev01', { command: 'true' })));
    assert.ok(peak <= 3, `opened ${peak} channels at once, cap was 3`);
    assert.strictEqual(inFlight, 0, 'every channel slot must be released');
  });
  await checkAsync('a burst still completes every call', async () => {
    const b = createBridge({ ...BASE_CFG, maxConcurrentChannels: 2 }, {
      clientFactory: () => ({
        on(ev, fn) { (this.h = this.h || {})[ev] = fn; return this; },
        connect() { setImmediate(() => this.h.ready()); },
        end() {},
        exec(cmd, opts, cb) {
          const { EventEmitter } = require('events');
          const ch = new EventEmitter();
          ch.stdin = { write: (d, f) => f && f(), end() {} };
          ch.stderr = new EventEmitter();
          cb(null, ch);
          setImmediate(() => { ch.emit('exit', 0); ch.emit('close', 0); });
          return ch;
        },
      }),
      configFile,
    });
    const rs = await Promise.all(Array.from({ length: 20 }, (_, i) => b.runCommand('dev01', { command: `echo ${i}` })));
    assert.strictEqual(rs.length, 20);
  });

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} passed, ${failures.length} failed`);
  if (failures.length > 0) {
    console.log('\nFailures:');
    for (const f of failures) console.log(`  - ${f.name}: ${f.message}`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('\nself-check crashed:', err);
  fs.rmSync(tmp, { recursive: true, force: true });
  process.exit(1);
});
