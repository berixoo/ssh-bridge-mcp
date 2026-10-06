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
  readFrom,
  statRemote,
  connectAlgorithms,
  downloadLimit,
  SHA1_REMOVALS,
  DEFAULT_MAX_DOWNLOAD,
  MAX_OUTPUT,
} = require(path.join(ROOT, 'src', 'ssh.js'));
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

function fakeSftp(source, { reportedSize, readError, fstatError } = {}) {
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
      const chunk = source.subarray(position, position + length);
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
