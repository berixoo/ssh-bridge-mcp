const crypto = require('crypto');
const { StringDecoder } = require('string_decoder');
const { failure } = require('./runtime');

function createExecutor({ runtime, makeExecCommand, killProcessGroup, shq, stripAnsi, maxOutput, graceMs }) {
  async function run(name, args, sudoPassword) {
    const inner = makeExecCommand(args);
    const lease = await runtime.acquire(name);
    const entry = lease.entry;
    const pidFile = !args.pty ? `/tmp/ssh-bridge-pid-${crypto.randomBytes(12).toString('hex')}` : null;
    const command = pidFile ? `bash -c ${shq(`echo $$ > ${pidFile}; trap 'rm -f ${pidFile}' EXIT;\n${inner}`)}` : inner;
    return new Promise((resolve, reject) => {
      const signal = runtime.context()?.signal;
      let channel;
      let channelClosed = false;
      let settled = false;
      let accepted = false;
      let dispatched = false;
      let grace;
      let exitCode = null;
      let exitSignal = null;
      let stdout = '';
      let stderr = '';
      let truncated = false;
      const outDecoder = new StringDecoder('utf8');
      const errDecoder = new StringDecoder('utf8');
      const append = (text, err) => {
        if (settled) return;
        const old = err ? stderr : stdout;
        const room = maxOutput - old.length;
        if (text.length > room) truncated = true;
        const value = old + text.slice(0, Math.max(0, room));
        if (err) stderr = value; else stdout = value;
      };
      const release = () => { entry.owners.delete(lost); lease.release(); };
      const close = () => {
        if (!channel) { runtime.invalidate(entry); release(); return; }
        if (channelClosed) { release(); return; }
        // Register before close: mocks and already-closed channels may acknowledge synchronously.
        const timer = setTimeout(() => { runtime.invalidate(entry); release(); }, 250);
        timer.unref?.();
        channel.once('close', () => { clearTimeout(timer); release(); });
        try { channel.close(); } catch (_) { clearTimeout(timer); runtime.invalidate(entry); release(); }
      };
      function finish(err, fields = {}) {
        if (settled) return;
        append(outDecoder.end(), false);
        append(errDecoder.end(), true);
        settled = true;
        clearTimeout(grace);
        signal?.removeEventListener('abort', abort);
        entry.owners.delete(lost);
        if (err) reject(err);
        else resolve({ exitCode, stdout: args.pty ? stripAnsi(stdout.replace(/\r/g, '')) : stdout,
          stderr: args.pty ? stripAnsi(stderr.replace(/\r/g, '')) : stderr,
          timedOut: false, truncated, ...(exitSignal ? { signal: exitSignal } : {}), ...fields });
      }
      function lost() {
        if (entry.closing) release();
        if (dispatched) finish(null, { outcome: 'unknown', error_code: 'OUTCOME_UNKNOWN', warning: 'SSH channel lost after dispatch; command may have executed. Not retried.' });
        else finish(failure('CONNECTION_FAILED', 'SSH connection closed before command channel was accepted'));
      }
      function abort() {
        if (settled) return;
        if (accepted) {
          if (pidFile) killProcessGroup(entry.client, pidFile).catch(() => {});
          else { try { channel?.signal('SIGKILL', () => {}); } catch (_) {} }
        }
        const reason = signal.reason;
        if (reason?.code === 'TIMEOUT') finish(null, { timedOut: true, outcome: dispatched ? 'unknown' : 'not_started', termination: 'best_effort' });
        else finish(reason || failure('CANCELLED', 'command cancelled'));
        close();
      }
      entry.owners.add(lost);
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) { abort(); return; }
      try {
        dispatched = true;
        entry.client.exec(command, args.pty ? { pty: { rows: 40, cols: 200, term: 'xterm-256color' } } : {}, (err, ch) => {
          if (settled) { try { ch?.close(); } catch (_) {} return; }
          if (err) {
            release();
            finish(Object.assign(failure('EXEC_OPEN_FAILED', `exec failed: ${err.message}`), { retrySafe: true }));
            return;
          }
          channel = ch;
          accepted = true;
          ch.on('data', (d) => append(outDecoder.write(d), false));
          ch.stderr?.on('data', (d) => append(errDecoder.write(d), true));
          ch.on('error', () => { lost(); close(); });
          ch.on('exit', (code, sig) => {
            exitCode = Number.isInteger(code) ? code : null;
            exitSignal = sig || null;
            grace = setTimeout(() => { finish(); close(); }, graceMs);
          });
          ch.on('close', (code, sig) => {
            channelClosed = true;
            release();
            if (exitCode === null && Number.isInteger(code)) exitCode = code;
            if (!exitSignal && sig) exitSignal = sig;
            if (exitCode === null && !exitSignal) lost(); else finish();
          });
          const input = (args.sudo && sudoPassword ? sudoPassword + '\n' : '') + (args.input ?? '');
          const stdin = ch.stdin || ch;
          stdin.on?.('error', () => {});
          try { stdin.end(input); } catch (e) { finish(e); close(); }
        });
      } catch (e) {
        release();
        // A synchronous throw means ssh2 did not enqueue the request.
        e.retrySafe = true;
        finish(e);
      }
    });
  }
  return { run };
}
module.exports = { createExecutor };
