'use strict';

// Standalone and offline: no bridge configuration, network, or existing tests.
const assert = require('assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { createFileTools } = require('../src/files');
const { checkLocalPath } = require('../src/paths');

const hash = (b) => crypto.createHash('sha256').update(b).digest('hex');
const error = (code, message = String(code)) => Object.assign(new Error(message), { code });
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshbridge-files-check-'));
let checks = 0;

class FakeSftp {
  constructor() {
    this.files = new Map();
    this.handles = new Map();
    this.next = 0;
    this.readBytes = 0;
    this.maxPacket = 7;
    this.calls = [];
  }
  put(p, value, mode = 0o100640) { this.files.set(p, { data: Buffer.from(value), mode }); }
  done(cb, err, result) { queueMicrotask(() => cb(err, result)); }
  entry(p) {
    const e = this.files.get(p);
    if (!e) throw error(2, 'not found');
    return e;
  }
  lstat(p, cb) {
    this.calls.push(['lstat', p]);
    try { const e = this.entry(p); this.done(cb, null, { size: e.reportedSize ?? e.data.length, mode: e.mode }); }
    catch (e) { this.done(cb, e); }
  }
  stat(p, cb) { this.lstat(p, cb); }
  fstat(h, cb) { this.lstat(this.handles.get(h), cb); }
  open(p, flag, mode, cb) {
    if (typeof mode === 'function') { cb = mode; mode = 0o600; }
    this.calls.push(['open', p, flag]);
    try {
      if (flag === 'wx') {
        if (this.files.has(p)) throw error(4, 'exists');
        this.put(p, '', 0o100000 | mode);
      } else this.entry(p);
      const h = ++this.next;
      this.handles.set(h, p);
      this.done(cb, null, h);
    } catch (e) { this.done(cb, e); }
  }
  close(h, cb) { this.handles.delete(h); this.done(cb); }
  read(h, buf, off, length, position, cb) {
    const source = this.entry(this.handles.get(h)).data;
    const n = Math.max(0, Math.min(length, this.maxPacket, source.length - position));
    source.copy(buf, off, position, position + n);
    this.readBytes += n;
    this.done(cb, null, n);
  }
  writeFile(p, bytes, cb) {
    this.calls.push(['writeFile', p]);
    const e = this.entry(p);
    e.data = Buffer.from(bytes);
    if (this.failWrite) { e.data = e.data.subarray(0, 1); return this.done(cb, error(4, 'injected interrupted write')); }
    this.done(cb);
  }
  chmod(p, mode, cb) {
    this.entry(p).mode = 0o100000 | mode;
    if (this.onChmod) this.onChmod(p);
    this.done(cb);
  }
  rename(a, b, cb) {
    this.calls.push(['rename', a, b]);
    if (this.files.has(b)) return this.done(cb, error(4, 'destination exists'));
    this.files.set(b, this.entry(a)); this.files.delete(a); this.done(cb);
  }
  ext_openssh_rename(a, b, cb) {
    this.calls.push(['posixRename', a, b]);
    if (this.renameUnsupported) return this.done(cb, error(8, 'unsupported'));
    if (this.failRename) return this.done(cb, error(4, 'injected rename failure'));
    this.files.set(b, this.entry(a)); this.files.delete(a); this.done(cb);
  }
  unlink(p, cb) {
    this.calls.push(['unlink', p]);
    if (!this.files.delete(p)) return this.done(cb, error(2));
    this.done(cb);
  }
  fastPut(local, remote, cb) {
    this.calls.push(['fastPut', remote]);
    this.writeFile(remote, fs.readFileSync(local), cb);
  }
}

const sftpCall = (s, method, ...args) => new Promise((resolve, reject) => s[method](...args, (e, value) => e ? reject(e) : resolve(value)));
// The injected helper deliberately exercises packet splits, including splits
// inside multibyte UTF-8. Production readFrom has the same raw-buffer contract.
async function readFrom(s, file, offset, limit) {
  const h = await sftpCall(s, 'open', file, 'r');
  try {
    const st = await sftpCall(s, 'fstat', h);
    const buf = Buffer.alloc(limit);
    let got = 0;
    while (got < limit) {
      const n = await new Promise((resolve, reject) => s.read(h, buf, got, limit - got, offset + got, (e, n) => e ? reject(e) : resolve(n)));
      if (!n) break;
      got += n;
    }
    return { buffer: buf.subarray(0, got), content: buf.subarray(0, got).toString('utf8'), size: offset + got, truncated: offset + got < st.size, error: null };
  } finally { await sftpCall(s, 'close', h); }
}

function fixture(extra = {}) {
  const s = new FakeSftp();
  let gets = 0;
  const f = createFileTools({
    cfg: {}, MAX_OUTPUT: 256, withSftp: async (_name, fn) => fn(s),
    mkdirp: async () => {}, statRemote: (s, p) => sftpCall(s, 'stat', p), readFrom,
    sftpError: (label, err) => Object.assign(new Error(`${label}: ${err.message}`), { code: err.code }),
    isDirMode: (st) => (st.mode & 0o170000) === 0o040000,
    isLinkMode: (st) => (st.mode & 0o170000) === 0o120000,
    checkLocalPath,
    fastGetInto: async (s, remote, local, size) => {
      ++gets;
      if (s.failGet) { fs.writeFileSync(local, 'partial'); throw error(4, 'interrupted download'); }
      const bytes = s.getBytes === undefined ? s.entry(remote).data : s.getBytes;
      fs.writeFileSync(local, bytes);
    },
    ...extra,
  });
  return { s, f, gets: () => gets };
}
const noStages = (s) => assert.equal([...s.files.keys()].filter((p) => p.includes('.sshbridge-')).length, 0);
const localStages = (dir) => fs.readdirSync(dir).filter((p) => p.startsWith('.sshbridge-'));
async function test(name, fn) { await fn(); ++checks; process.stdout.write(`ok ${checks} - ${name}\n`); }

async function main() {
  await test('whole read joins Unicode short packets and returns whole-file SHA-256', async () => {
    const { s, f } = fixture(); const bytes = Buffer.from('﻿你好😀\r\nsecond\r\n'); s.put('/a', bytes);
    const r = await f.readFile('h', '/a'); assert.equal(r.content, bytes.toString()); assert.equal(r.sha256, hash(bytes));
    assert.equal(r.hash_scope, 'whole_file'); assert.equal(r.truncated, false); assert.equal(s.handles.size, 0);
  });
  await test('full read above cap errors without scanning', async () => {
    const { s, f } = fixture(); s.put('/a', 'x'.repeat(257));
    await assert.rejects(f.readFile('h', '/a'), { code: 'FILE_TOO_LARGE' }); assert.equal(s.readBytes, 0);
  });
  await test('empty, exact-ceiling and zero-stat pseudo-file reads remain byte-accurate', async () => {
    const { s, f } = fixture();
    for (const value of ['', 'x'.repeat(256)]) {
      s.put('/a', value); const r = await f.readFile('h', '/a'); assert.equal(r.content, value); assert.equal(r.sha256, hash(value));
    }
    s.put('/a', '你好'); s.entry('/a').reportedSize = 0;
    assert.equal((await f.readFile('h', '/a')).content, '你好');
    s.put('/a', ''); const empty = await f.readFile('h', '/a', { tail: 1 });
    assert.equal(empty.range.start_line, null); assert.equal(empty.range.end_line, null); assert.equal(empty.hash_scope, 'whole_file');
  });
  await test('inclusive line range has truthful byte/line offsets and scoped hash', async () => {
    const { s, f } = fixture(); s.put('/a', '一\r\n二\r\n三\r\n');
    const r = await f.readFile('h', '/a', { start_line: 2, end_line: 2 });
    assert.equal(r.content, '二\r\n'); assert.equal(r.hash_scope, 'range'); assert.equal(r.sha256, hash('二\r\n'));
    assert.deepEqual(r.range, { start_byte: 5, end_byte: 10, start_line: 2, end_line: 2 }); assert.equal(r.next_offset, 10); assert.equal(r.truncated, false);
  });
  await test('line range beyond scan cap does not claim requested lines', async () => {
    const { s, f } = fixture(); s.put('/a', 'a\n'.repeat(1000));
    const r = await f.readFile('h', '/a', { start_line: 900, max_bytes: 19 });
    assert.equal(r.content, ''); assert.equal(r.truncated, true); assert.equal(r.scanned_bytes, 19);
    assert.equal(r.next_offset, 19); assert.equal(r.range.start_line, null); assert.equal(s.readBytes, 19);
  });
  await test('byte boundary never emits half a Unicode character', async () => {
    const { s, f } = fixture(); s.put('/a', 'a😀b');
    const r = await f.readFile('h', '/a', { max_bytes: 3 });
    assert.equal(r.content, 'a'); assert.equal(r.next_offset, 1); assert.equal(r.truncated, true); assert.equal(r.scanned_bytes, 3);
  });
  await test('head finishes at requested line without flagging unrelated remainder', async () => {
    const { s, f } = fixture(); s.put('/a', 'a\nb\nc\n'.repeat(100));
    const r = await f.readFile('h', '/a', { head: 1, max_bytes: 6 }); assert.equal(r.content, 'a\n'); assert.equal(r.truncated, false); assert.equal(r.hash_scope, 'range');
  });
  await test('tail scans only bounded suffix and never invents absolute line numbers', async () => {
    const { s, f } = fixture(); s.put('/a', 'a\n'.repeat(1000) + '你好\nlast\n');
    const r = await f.readFile('h', '/a', { tail: 2, max_bytes: 20 });
    assert.equal(r.content, '你好\nlast\n'); assert.equal(r.range.start_line, null); assert.equal(r.range.end_line, null);
    assert.equal(r.truncated, false); assert.equal(r.scanned_bytes, 20); assert.equal(s.readBytes, 20);
  });
  await test('tail too small for any whole line reports omission, not broken Unicode', async () => {
    const { s, f } = fixture(); s.put('/a', 'prefix' + '😀'.repeat(20));
    const r = await f.readFile('h', '/a', { tail: 1, max_bytes: 8 }); assert.equal(r.content, ''); assert.equal(r.truncated, true);
  });
  await test('invalid and incompatible ranges reject before any remote operation', async () => {
    const { f, s } = fixture();
    for (const opts of [{ head: 0 }, { tail: 1, head: 1 }, { head: 1, start_line: 2 }, { start_line: 2, end_line: 1 }, { max_bytes: 257 }, { max_bytes: NaN }]) {
      await assert.rejects(f.readFile('h', '/a', opts), { code: 'INVALID_ARGUMENT' });
    }
    assert.equal(s.calls.length, 0);
  });
  await test('patch preserves BOM/CRLF/unmodified bytes and original executable mode', async () => {
    const { s, f } = fixture(); const old = Buffer.from('﻿标题\r\nalpha\r\nbeta\r\n'); s.put('/a', old, 0o100751);
    const r = await f.patchFile('h', '/a', { expected_hash: hash(old), edits: [{ old_text: 'alpha', new_text: '你好😀' }, { old_text: 'beta', new_text: 'gamma' }] });
    assert.equal(s.entry('/a').data.toString(), '﻿标题\r\n你好😀\r\ngamma\r\n'); assert.equal(s.entry('/a').mode, 0o100751);
    assert.equal(r.sha256, hash(s.entry('/a').data)); assert.equal(r.edits, 2); noStages(s);
  });
  await test('dry-run leaves file and remote staging untouched', async () => {
    const { s, f } = fixture(); s.put('/a', 'old');
    const r = await f.patchFile('h', '/a', { expected_hash: hash('old'), edits: [{ old_text: 'old', new_text: 'new' }], dry_run: true });
    assert.equal(r.hash_scope, 'proposed_whole_file'); assert.equal(r.sha256, hash('new')); assert.equal(s.entry('/a').data.toString(), 'old');
    assert.equal(s.calls.filter((x) => x[0] === 'writeFile').length, 0); noStages(s);
  });
  await test('stale hash and missing hash cannot patch', async () => {
    const { s, f } = fixture(); s.put('/a', 'old');
    await assert.rejects(f.patchFile('h', '/a', { edits: [{ old_text: 'old', new_text: 'new' }] }), { code: 'INVALID_ARGUMENT' });
    await assert.rejects(f.patchFile('h', '/a', { expected_hash: hash('stale'), edits: [{ old_text: 'old', new_text: 'new' }] }), { code: 'FILE_CONFLICT' });
    assert.equal(s.entry('/a').data.toString(), 'old'); noStages(s);
  });
  await test('zero, duplicate, overlapping-occurrence and overlapping-edit matches reject', async () => {
    const { s, f } = fixture(); s.put('/a', 'aaa beta beta');
    for (const edits of [[{ old_text: 'missing', new_text: '' }], [{ old_text: 'beta', new_text: '' }], [{ old_text: 'aa', new_text: '' }], [{ old_text: 'aaa', new_text: '' }, { old_text: 'aaa b', new_text: '' }]]) {
      await assert.rejects(f.patchFile('h', '/a', { expected_hash: hash('aaa beta beta'), edits }), { code: 'PATCH_MATCH' });
    }
    assert.equal(s.entry('/a').data.toString(), 'aaa beta beta'); noStages(s);
  });
  await test('invalid UTF-8 and unpaired replacement surrogates reject without writing', async () => {
    const { s, f } = fixture(); const bad = Buffer.from([0xc3, 0x28]); s.put('/a', bad);
    await assert.rejects(f.patchFile('h', '/a', { expected_hash: hash(bad), edits: [{ old_text: '(', new_text: ')' }] }), { code: 'INVALID_ENCODING' });
    s.put('/a', 'old');
    await assert.rejects(f.patchFile('h', '/a', { expected_hash: hash('old'), edits: [{ old_text: 'old', new_text: '\ud800' }] }), { code: 'INVALID_ENCODING' });
    s.put('/a', '😀');
    await assert.rejects(f.patchFile('h', '/a', { expected_hash: hash('😀'), edits: [{ old_text: '\ud83d', new_text: 'a' }] }), { code: 'INVALID_ENCODING' }); noStages(s);
  });
  await test('patch expansion cannot exceed text byte ceiling', async () => {
    const { s, f } = fixture(); s.put('/a', 'old');
    await assert.rejects(f.patchFile('h', '/a', { expected_hash: hash('old'), edits: [{ old_text: 'old', new_text: '😀'.repeat(100) }] }), { code: 'FILE_TOO_LARGE' });
    assert.equal(s.entry('/a').data.toString(), 'old'); noStages(s);
  });
  await test('same-path concurrent patches serialize; exactly one stale caller loses', async () => {
    const { s, f } = fixture(); s.put('/a', 'old');
    const request = { expected_hash: hash('old'), edits: [{ old_text: 'old', new_text: 'new' }] };
    const results = await Promise.allSettled([f.patchFile('h', '/a', request), f.patchFile('h', '/a', request)]);
    assert.equal(results.filter((x) => x.status === 'fulfilled').length, 1);
    assert.equal(results.find((x) => x.status === 'rejected').reason.code, 'FILE_CONFLICT'); noStages(s);
  });
  await test('external modification after staging is caught by precommit hash recheck', async () => {
    const { s, f } = fixture(); s.put('/a', 'old'); s.onChmod = () => s.put('/a', 'external');
    await assert.rejects(f.patchFile('h', '/a', { expected_hash: hash('old'), edits: [{ old_text: 'old', new_text: 'new' }] }), { code: 'FILE_CONFLICT' });
    assert.equal(s.entry('/a').data.toString(), 'external'); noStages(s);
  });
  await test('interrupted staged write preserves old destination and cleans stage', async () => {
    const { s, f } = fixture(); s.put('/a', 'old'); s.failWrite = true;
    await assert.rejects(f.writeFile('h', '/a', 'new'), /interrupted/); assert.equal(s.entry('/a').data.toString(), 'old'); noStages(s);
  });
  await test('rename failure preserves old destination and never unlinks it', async () => {
    const { s, f } = fixture(); s.put('/a', 'old'); s.failRename = true;
    await assert.rejects(f.writeFile('h', '/a', 'new'), /rename failure/); assert.equal(s.entry('/a').data.toString(), 'old');
    assert.equal(s.calls.some((x) => x[0] === 'unlink' && x[1] === '/a'), false); noStages(s);
  });
  await test('unsupported POSIX rename fails safely; non-overwriting new-file rename still works', async () => {
    const { s, f } = fixture(); s.put('/a', 'old'); s.renameUnsupported = true;
    await assert.rejects(f.writeFile('h', '/a', 'new'), { code: 'ATOMIC_REPLACE_UNSUPPORTED' }); assert.equal(s.entry('/a').data.toString(), 'old'); noStages(s);
    s.ext_openssh_rename = undefined;
    await assert.rejects(f.writeFile('h', '/a', 'new'), { code: 'ATOMIC_REPLACE_UNSUPPORTED' });
    await f.writeFile('h', '/new', 'created'); assert.equal(s.entry('/new').data.toString(), 'created'); noStages(s);
  });
  await test('symlink and directory remote destinations reject clearly before staging', async () => {
    const { s, f } = fixture(); s.put('/link', 'target', 0o120777); s.put('/dir', '', 0o040755);
    await assert.rejects(f.writeFile('h', '/link', 'new'), { code: 'SYMLINK_DESTINATION' });
    await assert.rejects(f.writeFile('h', '/dir', 'new'), { code: 'IS_A_DIRECTORY' });
    await assert.rejects(f.patchFile('h', '/link', { expected_hash: hash('target'), edits: [{ old_text: 'target', new_text: '' }] }), { code: 'SYMLINK_DESTINATION' }); noStages(s);
  });
  const allowed = path.join(root, 'allowed'); fs.mkdirSync(allowed);
  const source = path.join(allowed, 'binary.bin'); const binary = Buffer.from([0, 1, 255, 254, 3]); fs.writeFileSync(source, binary);
  await test('binary upload uses fastPut/staging and preserves replacement permissions', async () => {
    const { s, f } = fixture(); s.put('/a', 'old', 0o100751);
    await f.upload('h', source, '/a'); assert.deepEqual(s.entry('/a').data, binary); assert.equal(s.entry('/a').mode, 0o100751);
    assert.equal(s.calls.filter((x) => x[0] === 'fastPut').length, 1); noStages(s);
    s.failWrite = true; await assert.rejects(f.upload('h', source, '/a'), /interrupted/); assert.deepEqual(s.entry('/a').data, binary); noStages(s);
  });
  await test('upload byte-count mismatch preserves original even after callback success', async () => {
    const { s, f } = fixture(); s.put('/a', 'old'); s.fastPut = (a, b, cb) => { s.put(b, ''); s.done(cb); };
    await assert.rejects(f.upload('h', source, '/a'), { code: 'TRANSFER_INTEGRITY' }); assert.equal(s.entry('/a').data.toString(), 'old'); noStages(s);
  });
  await test('local root boundary and credential file guard apply with and without roots', async () => {
    const protectedFile = path.join(allowed, 'protected.json'); fs.writeFileSync(protectedFile, 'fixture');
    const outside = path.join(root, 'allowed-sibling'); fs.mkdirSync(outside); const other = path.join(outside, 'a'); fs.writeFileSync(other, 'other');
    for (const cfg of [{}, { localRoots: [allowed] }]) {
      const { f } = fixture({ cfg, configFile: protectedFile });
      await assert.rejects(f.upload('h', protectedFile, '/a'), /configuration file/);
      await assert.rejects(f.download('h', '/a', protectedFile), /configuration file/);
      if (cfg.localRoots) {
        await assert.rejects(f.upload('h', other, '/a'), /outside/);
        await assert.rejects(f.download('h', '/a', path.join(outside, 'not-yet-created')), /outside/);
        await assert.rejects(f.download('h', '/a', path.join(allowed, '..', 'allowed-sibling', 'escape')), /outside/);
      }
    }
  });
  await test('symlinked parent cannot escape roots; symlink destination is rejected', async () => {
    const outside = path.join(root, 'linked-outside'); fs.mkdirSync(outside);
    fs.writeFileSync(path.join(outside, 'a'), 'outside');
    const link = path.join(allowed, 'junction');
    fs.symlinkSync(outside, link, process.platform === 'win32' ? 'junction' : 'dir');
    try {
      const { f } = fixture({ cfg: { localRoots: [allowed] } });
      await assert.rejects(f.upload('h', path.join(link, 'a'), '/a'), /outside/);
      await assert.rejects(f.download('h', '/a', path.join(link, 'new')), /outside/);
      await assert.rejects(f.download('h', '/a', link), { code: 'SYMLINK_DESTINATION' });
    } finally { fs.unlinkSync(link); }
  });
  await test('download uses protected staging, checks binary bytes, and replaces only after success', async () => {
    const checked = [];
    const { s, f } = fixture({ cfg: { localRoots: [allowed] }, checkLocalPath: (args) => { checked.push(args.localPath); return checkLocalPath(args); } });
    const target = path.join(allowed, 'download.bin'); fs.writeFileSync(target, 'old'); s.put('/a', binary);
    const r = await f.download('h', '/a', target); assert.equal(r.bytes, binary.length); assert.deepEqual(fs.readFileSync(target), binary);
    assert(checked.some((x) => path.basename(x).startsWith('.sshbridge-'))); assert.deepEqual(localStages(allowed), []);
    s.failGet = true; await assert.rejects(f.download('h', '/a', target), /interrupted/); assert.deepEqual(fs.readFileSync(target), binary); assert.deepEqual(localStages(allowed), []);
  });
  await test('download byte-count mismatch, including expected zero, preserves original', async () => {
    const { s, f } = fixture(); const target = path.join(allowed, 'mismatch.bin'); fs.writeFileSync(target, 'old');
    for (const expected of ['abc', '']) {
      s.put('/a', expected); s.getBytes = Buffer.from('different');
      await assert.rejects(f.download('h', '/a', target), { code: 'TRANSFER_INTEGRITY' }); assert.equal(fs.readFileSync(target, 'utf8'), 'old'); assert.deepEqual(localStages(allowed), []);
    }
    s.getBytes = Buffer.alloc(0); await f.download('h', '/a', target); assert.equal(fs.statSync(target).size, 0);
  });
  await test('download limit defaults to 2GiB, can be zero, and does not start oversized transfer', async () => {
    const { s, f, gets } = fixture(); s.put('/a', ''); s.entry('/a').reportedSize = 2 * 1024 ** 3 + 1;
    await assert.rejects(f.download('h', '/a', path.join(allowed, 'large')), { code: 'FILE_TOO_LARGE' }); assert.equal(gets(), 0);
    const unlimited = fixture({ cfg: { maxDownloadBytes: 0 } }); unlimited.s.put('/a', binary);
    await unlimited.f.download('h', '/a', path.join(allowed, 'unlimited')); assert.equal(unlimited.gets(), 1);
  });
  await test('directories are explicitly not transfers', async () => {
    const { s, f, gets } = fixture(); s.put('/dir', '', 0o040755); s.put('/a', 'a');
    await assert.rejects(f.upload('h', allowed, '/a'), { code: 'NOT_A_REGULAR_FILE' });
    await assert.rejects(f.download('h', '/dir', path.join(allowed, 'dir')), { code: 'IS_A_DIRECTORY' });
    await assert.rejects(f.download('h', '/a', allowed), { code: 'IS_A_DIRECTORY' }); assert.equal(gets(), 0);
  });
  process.stdout.write(`files-check: ${checks} checks passed\n`);
}

main().catch((err) => { console.error(err); process.exitCode = 1; }).finally(() => fs.rmSync(root, { recursive: true, force: true }));
