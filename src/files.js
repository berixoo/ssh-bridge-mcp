'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { TextDecoder } = require('util');

const DEFAULT_READ_LIMIT = 500 * 1024;
const DEFAULT_DOWNLOAD_LIMIT = 2 * 1024 * 1024 * 1024;
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

function failure(code, message) {
  return Object.assign(new Error(message), { code });
}

function positiveInteger(value, key, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw failure('INVALID_ARGUMENT', `${key} must be an integer from 1 to ${maximum}`);
  }
  return value;
}

// Withhold an incomplete final UTF-8 character at a byte-budget boundary. The
// offset describes bytes returned, not the length of the decoded JS string.
function utf8End(bytes) {
  if (!bytes.length) return 0;
  let lead = bytes.length - 1;
  while (lead >= 0 && (bytes[lead] & 0xc0) === 0x80) --lead;
  if (lead < 0) return bytes.length;
  const b = bytes[lead];
  const width = b >= 0xc2 && b <= 0xdf ? 2 : b >= 0xe0 && b <= 0xef ? 3 : b >= 0xf0 && b <= 0xf4 ? 4 : 1;
  return bytes.length - lead < width ? lead : bytes.length;
}

function strictText(bytes) {
  try {
    // ignoreBOM=true retains U+FEFF in the string, so encoding the result keeps
    // the original BOM. No newline conversion is performed anywhere.
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch (_) {
    throw failure('INVALID_ENCODING', 'patch_file requires valid UTF-8 text');
  }
}

function createFileTools({
  withSftp, cfg = {}, configFile, MAX_OUTPUT = DEFAULT_READ_LIMIT,
  mkdirp, statRemote, readFrom, sftpError, isDirMode, isLinkMode,
  checkLocalPath, fastGetInto, wait = (promise) => promise,
}) {
  const queues = new Map();
  const readLimit = positiveInteger(MAX_OUTPUT, 'MAX_OUTPUT');
  const wrap = (label, err) => sftpError ? sftpError(label, err) : err;
  const call = (s, method, ...args) => new Promise((resolve, reject) => {
    // Promise executor also captures synchronous errors such as an unsupported
    // OpenSSH extension in ssh2.
    s[method](...args, (err, result) => err ? reject(wrap(method, err)) : resolve(result));
  });

  // Includes write/upload so a bridge write cannot race its own patch. This is
  // optimistic conflict detection, not filesystem CAS against external writers.
  async function serialized(name, file, fn) {
    const key = JSON.stringify([name, path.posix.normalize(file)]);
    const previous = queues.get(key) || Promise.resolve();
    const current = previous.catch(() => {}).then(fn);
    queues.set(key, current);
    current.finally(() => { if (queues.get(key) === current) queues.delete(key); }).catch(() => {});
    return wait(current);
  }

  async function destination(s, file) {
    let st;
    try { st = await call(s, 'lstat', file); }
    catch (err) {
      if (err.code === 2 || err.code === 'ENOENT') return null;
      throw err;
    }
    if (isLinkMode(st)) throw failure('SYMLINK_DESTINATION', `refusing symlink destination: ${file}`);
    if (isDirMode(st)) throw failure('IS_A_DIRECTORY', `${file}: IS_A_DIRECTORY (only single files are supported)`);
    if (typeof st.mode === 'number' && (st.mode & 0o170000) !== 0o100000) {
      throw failure('NOT_A_REGULAR_FILE', `refusing non-regular destination: ${file}`);
    }
    return st;
  }

  async function cleanupRemote(s, stage, error) {
    try { await call(s, 'unlink', stage); }
    catch (cleanup) {
      if (cleanup.code !== 2 && cleanup.code !== 'ENOENT') {
        error.cleanup_error = `could not remove staging file ${stage}: ${cleanup.message}`;
      }
    }
  }

  async function stagedRemote(s, file, size, writer, beforeCommit) {
    await destination(s, file);
    await mkdirp(s, path.posix.dirname(file));
    const stage = path.posix.join(path.posix.dirname(file), `.sshbridge-${crypto.randomBytes(16).toString('hex')}.tmp`);
    let owned = false;
    try {
      const h = await call(s, 'open', stage, 'wx', 0o600);
      owned = true;
      await call(s, 'close', h);
      await writer(stage);
      const written = await statRemote(s, stage);
      if (written.size !== size) throw failure('TRANSFER_INTEGRITY', `staging wrote ${written.size} of ${size} bytes`);
      const current = await destination(s, file);
      if (current && typeof s.ext_openssh_rename !== 'function') {
        throw failure('ATOMIC_REPLACE_UNSUPPORTED', 'server cannot safely overwrite files: OpenSSH POSIX rename is required; original preserved');
      }
      // Preserve permissions, including executable bits, rather than inheriting
      // the restrictive temporary-file mode on replacements.
      await call(s, 'chmod', stage, current ? current.mode & 0o7777 : 0o644);
      if (beforeCommit) await beforeCommit();
      // Recheck the leaf after the potentially asynchronous conflict check.
      const final = await destination(s, file);
      if (final) {
        if (typeof s.ext_openssh_rename !== 'function') {
          throw failure('ATOMIC_REPLACE_UNSUPPORTED', 'server cannot safely overwrite files; original preserved');
        }
        try { await call(s, 'ext_openssh_rename', stage, file); }
        catch (err) {
          // In particular, never unlink the old destination to emulate rename.
          if (err.code === 8 || /unsupported|not supported/i.test(err.message)) {
            throw failure('ATOMIC_REPLACE_UNSUPPORTED', 'server does not support OpenSSH POSIX rename; original preserved');
          }
          throw err;
        }
      } else {
        // SFTP v3 rename refuses an existing destination, unlike POSIX rename.
        await call(s, 'rename', stage, file);
      }
      owned = false;
    } catch (err) {
      if (owned) await cleanupRemote(s, stage, err);
      throw err;
    }
  }

  async function boundedRead(s, file, offset, budget) {
    const r = await readFrom(s, file, offset, budget);
    if (r.error) throw wrap(`read_file ${file}`, r.error);
    if (!Buffer.isBuffer(r.buffer)) {
      throw failure('READ_PROTOCOL', 'readFrom must return raw bytes in buffer');
    }
    if (r.buffer.length > budget || r.size !== offset + r.buffer.length) {
      throw failure('READ_PROTOCOL', 'read offset changed or exceeded byte budget; retry the read');
    }
    return r;
  }

  async function whole(s, file) {
    const st = await statRemote(s, file);
    if (isDirMode(st)) throw failure('IS_A_DIRECTORY', `${file}: IS_A_DIRECTORY (use list_dir)`);
    if (st.size > readLimit) throw failure('FILE_TOO_LARGE', `read_file ${file}: exceeds the ${readLimit}-byte limit; use a range or download`);
    const r = await boundedRead(s, file, 0, readLimit);
    if (r.truncated || r.buffer.length < st.size) {
      throw failure('FILE_TOO_LARGE', `read_file ${file}: not read completely within the ${readLimit}-byte limit`);
    }
    return r.buffer;
  }

  async function readFile(name, file, options = {}) {
    const keys = ['start_line', 'end_line', 'head', 'tail', 'max_bytes'];
    const partial = keys.some((key) => options[key] !== undefined);
    if (!partial) return withSftp(name, async (s) => {
      const bytes = await whole(s, file);
      return { content: bytes.toString('utf8'), sha256: sha256(bytes), hash_scope: 'whole_file', bytes: bytes.length, truncated: false };
    });
    const budget = options.max_bytes === undefined ? readLimit : positiveInteger(options.max_bytes, 'max_bytes', readLimit);
    for (const key of ['start_line', 'end_line', 'head', 'tail']) {
      if (options[key] !== undefined) positiveInteger(options[key], key);
    }
    if ((options.head !== undefined && options.tail !== undefined) ||
        ((options.head !== undefined || options.tail !== undefined) && (options.start_line !== undefined || options.end_line !== undefined))) {
      throw failure('INVALID_ARGUMENT', 'head, tail and line ranges are mutually exclusive');
    }
    const firstLine = options.start_line === undefined ? 1 : options.start_line;
    const lastLine = options.head === undefined ? (options.end_line === undefined ? Infinity : options.end_line) : options.head;
    if (lastLine < firstLine) throw failure('INVALID_ARGUMENT', 'end_line must not precede start_line');
    return withSftp(name, async (s) => {
      const st = await statRemote(s, file);
      if (isDirMode(st)) throw failure('IS_A_DIRECTORY', `${file}: IS_A_DIRECTORY (use list_dir)`);
      const offset = options.tail === undefined ? 0 : Math.max(0, st.size - budget);
      const r = await boundedRead(s, file, offset, budget);
      const scanned = r.buffer;
      const completeEnd = !r.truncated && offset + scanned.length >= st.size;
      const end = completeEnd ? scanned.length : utf8End(scanned);
      let from = 0;
      let to = end;
      let startLine = offset === 0 ? 1 : null;
      let endLine = startLine;
      let satisfied = false;
      if (options.tail !== undefined) {
        // A window starting mid-file has an unknown absolute line number. Drop
        // its first partial line rather than inventing a number or broken text.
        if (offset > 0) {
          const lf = scanned.indexOf(10);
          from = lf < 0 || lf >= end ? end : lf + 1;
        }
        const starts = [];
        for (let p = from; p < end;) {
          starts.push(p);
          const lf = scanned.indexOf(10, p);
          p = lf < 0 || lf >= end ? end : lf + 1;
        }
        const skip = Math.max(0, starts.length - options.tail);
        if (starts.length) from = starts[skip];
        if (offset === 0) startLine = starts.length ? skip + 1 : null;
        endLine = startLine === null ? null : startLine + starts.length - skip - 1;
        satisfied = completeEnd && (offset === 0 || starts.length >= options.tail);
      } else {
        let line = 1;
        from = end;
        to = end;
        for (let p = 0; p < end;) {
          const lf = scanned.indexOf(10, p);
          const next = lf < 0 || lf >= end ? end : lf + 1;
          if (line === firstLine) from = p;
          if (line >= firstLine && line <= lastLine) {
            endLine = line;
            to = next;
          }
          if (line === lastLine) {
            satisfied = next < end || scanned[next - 1] === 10 || completeEnd;
            break;
          }
          p = next;
          ++line;
        }
        if (from === end) { startLine = null; endLine = null; }
        else startLine = firstLine;
        if (completeEnd) satisfied = true;
      }
      const selected = scanned.subarray(from, to);
      const all = offset === 0 && from === 0 && to === scanned.length && completeEnd;
      return {
        content: selected.toString('utf8'), bytes: selected.length,
        sha256: sha256(selected), hash_scope: all ? 'whole_file' : 'range',
        range: { start_byte: offset + from, end_byte: offset + to, start_line: startLine, end_line: endLine },
        // Half-open byte range. For a scan that has not reached start_line,
        // resume after scanned bytes rather than claiming lines were returned.
        next_offset: offset + (selected.length ? to : end), scanned_bytes: scanned.length,
        truncated: !satisfied, file_size: st.size,
      };
    });
  }

  async function writeFile(name, file, content, options = {}) {
    if (typeof content !== 'string' && !Buffer.isBuffer(content)) throw failure('INVALID_ARGUMENT', 'content must be text or a Buffer');
    const bytes = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
    return serialized(name, file, () => withSftp(name, async (s) => {
      await stagedRemote(s, file, bytes.length, (stage) => call(s, 'writeFile', stage, bytes));
      return { ok: true, bytes: bytes.length, sha256: sha256(bytes), hash_scope: 'whole_file' };
    }));
  }

  async function patchFile(name, file, { expected_hash, edits, dry_run = false } = {}) {
    if (typeof expected_hash !== 'string' || !/^[a-fA-F0-9]{64}$/.test(expected_hash)) {
      throw failure('INVALID_ARGUMENT', 'patch_file requires expected_hash: a whole-file SHA-256');
    }
    if (!Array.isArray(edits) || !edits.length || typeof dry_run !== 'boolean') throw failure('INVALID_ARGUMENT', 'patch_file requires nonempty edits and a boolean dry_run');
    return serialized(name, file, () => withSftp(name, async (s) => {
      await destination(s, file);
      const original = await whole(s, file);
      const oldHash = sha256(original);
      if (oldHash !== expected_hash.toLowerCase()) throw failure('FILE_CONFLICT', 'patch_file: expected_hash does not match current whole-file SHA-256');
      const text = strictText(original);
      const spans = edits.map((edit) => {
        if (!edit || typeof edit.old_text !== 'string' || !edit.old_text.length || typeof edit.new_text !== 'string') {
          throw failure('INVALID_ARGUMENT', 'each edit requires nonempty literal old_text and string new_text');
        }
        if (Buffer.byteLength(edit.new_text, 'utf8') > readLimit) throw failure('FILE_TOO_LARGE', `patched file exceeds the ${readLimit}-byte text limit`);
        if (strictText(Buffer.from(edit.old_text)) !== edit.old_text || strictText(Buffer.from(edit.new_text)) !== edit.new_text) {
          throw failure('INVALID_ENCODING', 'edit text contains an unpaired Unicode surrogate');
        }
        const start = text.indexOf(edit.old_text);
        // Search from start+1, not old_text.length: overlapping occurrences
        // such as aa in aaa are multiple matches too.
        if (start < 0 || text.indexOf(edit.old_text, start + 1) !== -1) {
          throw failure('PATCH_MATCH', 'each old_text must match exactly once in the original file');
        }
        return { start, end: start + edit.old_text.length, replacement: edit.new_text };
      }).sort((a, b) => a.start - b.start);
      for (let i = 1; i < spans.length; ++i) {
        if (spans[i].start < spans[i - 1].end) throw failure('PATCH_MATCH', 'patch edits must not overlap');
      }
      const expectedBytes = spans.reduce((size, e) => size - Buffer.byteLength(text.slice(e.start, e.end), 'utf8') + Buffer.byteLength(e.replacement, 'utf8'), original.length);
      if (expectedBytes > readLimit) throw failure('FILE_TOO_LARGE', `patched file exceeds the ${readLimit}-byte text limit`);
      const pieces = [];
      let cursor = 0;
      for (const e of spans) {
        pieces.push(text.slice(cursor, e.start), e.replacement);
        cursor = e.end;
      }
      pieces.push(text.slice(cursor));
      const bytes = Buffer.from(pieces.join(''), 'utf8');
      if (bytes.length > readLimit) throw failure('FILE_TOO_LARGE', `patched file exceeds the ${readLimit}-byte text limit`);
      const hash = sha256(bytes);
      if (!dry_run) await stagedRemote(s, file, bytes.length, (stage) => call(s, 'writeFile', stage, bytes), async () => {
        if (sha256(await whole(s, file)) !== oldHash) throw failure('FILE_CONFLICT', 'patch_file: file changed before commit; original not overwritten');
      });
      return { ok: true, dry_run, edits: spans.length, bytes: bytes.length, previous_hash: oldHash, sha256: hash, hash_scope: dry_run ? 'proposed_whole_file' : 'whole_file' };
    }));
  }

  function localPath(local, tool, rejectLink = false) {
    if (rejectLink) {
      try {
        const st = fs.lstatSync(path.resolve(local));
        if (st.isSymbolicLink()) throw failure('SYMLINK_DESTINATION', `refusing symlink destination: ${local}`);
        if (st.isDirectory()) throw failure('IS_A_DIRECTORY', `${local}: only single files are supported`);
        if (!st.isFile()) throw failure('NOT_A_REGULAR_FILE', `refusing non-regular destination: ${local}`);
      } catch (err) { if (err.code !== 'ENOENT') throw err; }
    }
    return checkLocalPath({ localPath: local, cfg, configFile, tool });
  }

  async function upload(name, local, remote, options = {}) {
    const source = localPath(local, 'upload');
    const st = fs.statSync(source);
    if (!st.isFile()) throw failure('NOT_A_REGULAR_FILE', 'upload supports only single regular files, not directories');
    return serialized(name, remote, () => withSftp(name, async (s) => {
      await stagedRemote(s, remote, st.size, (stage) => call(s, 'fastPut', source, stage));
      return { ok: true, bytes: st.size };
    }));
  }

  async function download(name, remote, local, options = {}) {
    const target = localPath(local, 'download', true);
    const limit = cfg.maxDownloadBytes === undefined ? DEFAULT_DOWNLOAD_LIMIT : cfg.maxDownloadBytes;
    if (!Number.isSafeInteger(limit) || limit < 0) throw failure('INVALID_ARGUMENT', 'maxDownloadBytes must be a nonnegative integer (0 = unlimited)');
    return withSftp(name, async (s) => {
      const st = await statRemote(s, remote);
      if (isDirMode(st)) throw failure('IS_A_DIRECTORY', 'download supports only single files, not directories');
      if (typeof st.mode === 'number' && (st.mode & 0o170000) !== 0o100000) throw failure('NOT_A_REGULAR_FILE', 'download supports only regular files');
      if (!Number.isSafeInteger(st.size) || st.size < 0) throw failure('TRANSFER_INTEGRITY', 'invalid remote file size');
      if (limit > 0 && st.size > limit) throw failure('FILE_TOO_LARGE', `download ${remote}: ${st.size} bytes exceeds maxDownloadBytes (${limit}; 0 = unlimited)`);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      const stage = path.join(path.dirname(target), `.sshbridge-${crypto.randomBytes(16).toString('hex')}.tmp`);
      // The generated staging path goes through the same credential/root guard.
      localPath(stage, 'download', true);
      let owned = false;
      try {
        fs.closeSync(fs.openSync(stage, 'wx', 0o600));
        owned = true;
        await fastGetInto(s, remote, stage, st.size);
        const bytes = fs.statSync(stage).size;
        if (bytes !== st.size) throw failure('TRANSFER_INTEGRITY', `download ${remote}: wrote ${bytes} of ${st.size} bytes`);
        const after = await statRemote(s, remote);
        if (after.size !== st.size) throw failure('TRANSFER_INTEGRITY', 'remote size changed during download');
        if (localPath(local, 'download', true) !== target) throw failure('LOCAL_PATH_CHANGED', 'local destination resolved to a different path during download');
        localPath(stage, 'download', true);
        try { fs.chmodSync(stage, fs.statSync(target).mode & 0o7777); }
        catch (err) {
          if (err.code !== 'ENOENT') throw err;
          fs.chmodSync(stage, 0o666 & ~process.umask());
        }
        fs.renameSync(stage, target);
        owned = false;
        return { ok: true, bytes };
      } catch (err) {
        if (owned) {
          try { fs.unlinkSync(stage); }
          catch (cleanup) { if (cleanup.code !== 'ENOENT') err.cleanup_error = `could not remove local staging file: ${cleanup.message}`; }
        }
        throw err;
      }
    });
  }

  return { readFile, writeFile, patchFile, upload, download };
}

module.exports = { createFileTools };
