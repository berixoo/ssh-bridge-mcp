// A serialized, non-PTY bash stream. Each submission is one parsed compound
// command; multiline scripts cannot finish at an intermediate shell prompt.
const crypto = require('crypto');
const { StringDecoder } = require('string_decoder');
const { failure } = require('./runtime');

function createSessions({ runtime, shq, maxOutput }) {
  const sessions = new Map();
  const queues = new Map();
  const lost = new Set();
  function discard(rec, explicit = false) {
    if (!rec || rec.closed) return;
    rec.closed = true;
    if (rec.channel && !explicit) lost.add(rec.name);
    if (sessions.get(rec.name) === rec) sessions.delete(rec.name);
    rec.rejectOpen?.(failure('CONNECTION_CLOSED', 'persistent shell closed during opening'));
    rec.active?.fail(failure('OUTCOME_UNKNOWN', 'persistent shell closed; command may have executed'));
    rec.entry?.owners.delete(rec.dispose);
    if (rec.channel && !rec.channelClosed && !rec.entry.closing) {
      const timer = setTimeout(() => { runtime.invalidate(rec.entry); rec.lease?.release(); }, 250);
      timer.unref?.();
      rec.channel.once('close', () => { clearTimeout(timer); rec.lease?.release(); });
      try { rec.channel.close(); }
      catch (_) { clearTimeout(timer); runtime.invalidate(rec.entry); rec.lease?.release(); }
    } else {
      if (rec.entry && !rec.channel && !rec.entry.closing) runtime.invalidate(rec.entry);
      rec.lease?.release();
    }
  }
  async function open(name) {
    const old = sessions.get(name);
    if (old && !old.closed) return old;
    const lease = await runtime.acquire(name);
    const rec = { name, lease, entry: lease.entry, closed: false, channelClosed: false, active: null };
    rec.dispose = () => discard(rec);
    rec.entry.owners.add(rec.dispose);
    sessions.set(name, rec);
    try {
      let expired = false;
      const pending = new Promise((resolve, reject) => {
        rec.rejectOpen = reject;
        try {
          rec.entry.client.exec('bash --noprofile --norc -O expand_aliases 2>&1', {}, (err, ch) => {
            if (expired || rec.closed) { try { ch?.close(); } catch (_) {} return; }
            if (err) return reject(err);
            rec.channel = ch;
            const stdoutDecoder = new StringDecoder('utf8');
            const stderrDecoder = new StringDecoder('utf8');
            ch.on('data', (d) => rec.active?.data(stdoutDecoder.write(d)));
            ch.stderr?.on('data', (d) => rec.active?.data(stderrDecoder.write(d)));
            ch.on('close', () => { rec.channelClosed = true; discard(rec); });
            ch.on('error', () => discard(rec));
            resolve(rec);
          });
        } catch (e) { reject(e); }
      });
      return await runtime.wait(pending, () => { expired = true; discard(rec); });
    } catch (e) { discard(rec); throw e; }
  }
  function run(name, args) {
    if (args.sudo || args.input !== undefined || args.pty) {
      return Promise.reject(failure('UNSUPPORTED_OPTIONS', 'session mode supports cwd/env/pipefail, not sudo/input/pty; use one-shot execution for these'));
    }
    const prev = (queues.get(name) || Promise.resolve()).catch(() => {});
    const next = prev.then(async () => {
      runtime.check();
      const rec = await open(name);
      runtime.check();
      const token = crypto.randomBytes(16).toString('hex');
      const prefix = `\x1b]133;D;${token};`;
      let command = '';
      if (args.env) for (const [key, value] of Object.entries(args.env)) {
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) throw failure('INVALID_ENV', `invalid environment variable name: ${key}`);
        command += `export ${key}=${shq(String(value))}\n`;
      }
      if (args.pipefail !== undefined) command += args.pipefail ? 'set -o pipefail\n' : 'set +o pipefail\n';
      const body = command + args.command;
      const script = args.cwd ? `if cd -- ${shq(args.cwd)}; then eval -- ${shq(body)}; else false; fi` : `eval -- ${shq(body)}`;
      // Literal shell quoting keeps the complete eval script inside one compound command.
      const line = `{ ${script}; __bridge_rc=$?; printf '\\033]133;D;${token};%s\\007' "$__bridge_rc"; }\n`;
      let output = '';
      let pending = '';
      let truncated = false;
      const append = (text) => {
        const room = maxOutput - output.length;
        if (text.length > room) truncated = true;
        output += text.slice(0, Math.max(0, room));
      };
      const result = new Promise((resolve, reject) => {
        rec.active = {
          fail: reject,
          data(text) {
            pending += text;
            const start = pending.indexOf(prefix);
            if (start >= 0) {
              const end = pending.indexOf('\x07', start + prefix.length);
              if (end >= 0) {
                const code = pending.slice(start + prefix.length, end);
                if (/^\d+$/.test(code)) {
                  append(pending.slice(0, start));
                  rec.active = null;
                  const warning = lost.delete(name) ? 'Persistent shell was recreated; its previous cwd/env/functions/aliases are gone. Managed background jobs may still be running.' : undefined;
                  return resolve({ exitCode: Number(code), stdout: output, stderr: '', timedOut: false, truncated, session: true,
                    ...(warning ? { warning } : {}) });
                }
              }
            }
            // Keep only a small possible partial marker while draining output.
            const keep = prefix.length + 16;
            if (pending.length > keep) { append(pending.slice(0, -keep)); pending = pending.slice(-keep); }
          },
        };
        try { rec.channel.write(line); } catch (e) { reject(e); }
      });
      try { return await runtime.wait(result, () => discard(rec)); }
      catch (e) {
        discard(rec);
        if (e.code === 'OUTCOME_UNKNOWN' || e.code === 'TIMEOUT') {
          append(pending);
          return { exitCode: null, stdout: output, stderr: '', timedOut: e.code === 'TIMEOUT', truncated, session: true,
            outcome: 'unknown', error_code: e.code, warning: 'Shell transaction did not acknowledge completion. It may have executed; not retried.',
            ...(e.code === 'TIMEOUT' ? { termination: 'best_effort' } : {}) };
        }
        throw e;
      }
      finally { rec.active = null; }
    });
    queues.set(name, next);
    next.finally(() => { if (queues.get(name) === next) queues.delete(name); }).catch(() => {});
    // Only the queue gate needs this outer wait. Once dispatched, the inner
    // wait owns timeout cleanup and preserves partial output in its result.
    // Keep `next` as the queue barrier even when a queued caller cancels.
    return runtime.wait(prev).then(() => next);
  }
  function close(name) { const rec = sessions.get(name); discard(rec, true); lost.delete(name); return { ok: true, closed: !!rec }; }
  function shutdown() { for (const rec of sessions.values()) discard(rec, true); lost.clear(); }
  return { run, close, shutdown };
}
module.exports = { createSessions };
