'use strict';

const crypto = require('crypto');
const { StringDecoder } = require('string_decoder');

const VERSION = 1;
const MAX_LOG = 1024 * 1024;
const TAG = 'SSH_BRIDGE_JOB_V1';
const TERMINAL = new Set(['succeeded', 'failed', 'stopped']);

// Linux + bash + util-linux setsid. No daemon or shell-sourced metadata. The
// supervisor remains the session leader until its descendants have exited, so
// stop can verify an anchor even when the command forks or ignores TERM.
// Commands that deliberately create another session (daemonize/setsid) escape
// this scope; without cgroups/pidfds this is not a process-containment boundary.
const CONTROL = String.raw`#!/bin/bash
set -u
umask 077
action=$1 d=$2
proc() {
  local line rest
  [[ $1 =~ ^[1-9][0-9]*$ ]] || return 1
  IFS= read -r line < "/proc/$1/stat" 2>/dev/null || return 1
  rest=@{line##*) }
  read -ra fields <<< "$rest"
  [[ @{#fields[@]} -ge 20 ]] || return 1
  state=@{fields[0]} pg=@{fields[2]} sid=@{fields[3]} tick=@{fields[19]}
}
identity() {
  [[ -r "$d/identity" ]] || return 1
  read -r pid start boot < "$d/identity" || return 1
  [[ $pid =~ ^[1-9][0-9]*$ && $start =~ ^[0-9]+$ ]] || return 1
  [[ $boot == "$(< /proc/sys/kernel/random/boot_id)" ]] || return 1
  proc "$pid" && [[ $tick == "$start" && $pg == "$pid" && $sid == "$pid" && $state != Z && $state != X ]]
}
members() {
  local f p own=$BASHPID
  for f in /proc/[0-9]*/stat; do
    p=@{f#/proc/}; p=@{p%/stat}
    [[ $p != "$pid" && $p != "$own" ]] || continue
    if proc "$p" && [[ $sid == "$pid" && $state != Z && $state != X ]]; then
      printf '%s %s\n' "$p" "$tick"
    fi
  done
}
signal_members() {
  local p t
  while read -r p t; do
    # Recheck each identity immediately before signalling, not just kill -0.
    if identity && proc "$p" && [[ $tick == "$t" && $sid == "$pid" ]]; then
      kill -s "$1" -- "$p" 2>/dev/null || :
    fi
  done < <(members)
}
finish() {
  # Atomic, first-writer-wins completion without a stale lock after disconnect.
  local tmp="$d/result.$BASHPID.tmp"
  printf '%s %s\n' "$1" "$2" > "$tmp" || return 1
  ln -- "$tmp" "$d/result" 2>/dev/null || [[ -r "$d/result" ]]
  local rc=$?
  rm -f -- "$tmp"
  return "$rc"
}
report() {
  local status=unknown code=-
  pid=-
  if [[ -r "$d/result" ]]; then
    read -r status code < "$d/result"
    [[ ! -r "$d/identity" ]] || read -r pid start boot < "$d/identity"
  elif identity; then
    status=running
  fi
  printf 'SSH_BRIDGE_JOB_V1\t%s\t%s\t%s\n' "$status" "$pid" "$code"
}
case "$action" in
  run)
    trap ':' TERM INT
    cd -- "$3" || { printf 'invalid cwd\n' > "$d/launch.error"; exit 1; }
    pid=$$
    proc "$pid" && [[ $pg == "$pid" && $sid == "$pid" ]] || { printf 'setsid failed\n' > "$d/launch.error"; exit 1; }
    printf '%s %s %s\n' "$pid" "$tick" "$(< /proc/sys/kernel/random/boot_id)" > "$d/identity.tmp"
    mv -- "$d/identity.tmp" "$d/identity" || exit 1
    "$BASH" -c 'source "$1" || exit; exec "$2" "$3"' -- "$d/environment.sh" "$BASH" "$d/command.sh" < "$d/input" >> "$d/output.log" 2>&1 &
    child=$!
    while :; do
      wait "$child"; rc=$?
      if ! proc "$child" || [[ $state == Z || $state == X ]]; then break; fi
    done
    # A stop request keeps the identity anchor alive for the external stopper.
    while [[ -e "$d/stop.request" || -n "$(members)" ]]; do sleep 0.1; done
    if [[ $rc == 0 ]]; then finish succeeded "$rc"; else finish failed "$rc"; fi
    ;;
  launch)
    cd -- "$3" || exit 1
    mkdir "$d/launch.lock" || exit 1
    nohup setsid bash "$d/control.sh" run "$d" "$PWD" > "$d/launcher.log" 2>&1 < /dev/null &
    for ((i=0; i<50; i++)); do
      if [[ -s "$d/identity" ]]; then report; exit 0; fi
      if [[ -s "$d/launch.error" ]]; then cat -- "$d/launch.error" >&2; exit 1; fi
      sleep 0.1
    done
    printf 'launch acknowledgement missing; outcome unknown\n' >&2
    exit 75
    ;;
  status) report ;;
  stop)
    if [[ -r "$d/result" ]]; then report; exit 0; fi
    if ! identity; then report; exit 0; fi
    # Repeated/concurrent stops are safe and leave no lock to strand recovery.
    : > "$d/stop.request"
    # Freeze only the supervisor, not the workload. This preserves the anchor
    # and prevents its polling sleeps from racing the final descendant sweep.
    if identity; then kill -s STOP -- "$pid" || exit 1; else report; exit 0; fi
    signal_members TERM
    if identity; then kill -s TERM -- "$pid" 2>/dev/null || :; fi
    code=143
    for ((i=0; i<$3; i++)); do
      [[ -n "$(members)" ]] || break
      sleep 0.1
    done
    # Repeat for forks during termination; never signal a recycled leader.
    for ((i=0; i<20; i++)); do
      [[ -n "$(members)" ]] || break
      identity || { report; exit 0; }
      signal_members KILL
      code=137
      sleep 0.1
    done
    if [[ -n "$(members)" ]]; then report; exit 0; fi
    if identity; then kill -s KILL -- "$pid" 2>/dev/null || :; fi
    for ((i=0; i<20; i++)); do
      identity || break
      sleep 0.1
    done
    if identity; then report; exit 0; fi
    finish stopped "$code"
    report
    ;;
  cleanup)
    [[ -r "$d/result" ]] || { printf 'not terminal\n' >&2; exit 1; }
    read -r status code < "$d/result"
    case "$status" in succeeded|failed|stopped) ;; *) exit 1 ;; esac
    # Completion is atomic but its writer may still be exiting for a moment.
    for ((i=0; i<10; i++)); do identity || break; sleep 0.1; done
    if identity || [[ -n "$(members)" ]]; then printf 'job still active\n' >&2; exit 1; fi
    rm -r -- "$d"
    ;;
  *) exit 2 ;;
esac
`.replaceAll('@{', '${');

function jobError(code, message, extra = {}) {
  return Object.assign(new Error(message), { code, ...extra });
}

/**
 * All callbacks are injected; importing this module opens no connections.
 * start: {command,cwd?,env?,input?,sudo?:false}; logs: {cursor?,limit?};
 * stop: {graceMs?:2000,cleanup?:false}; list: {cursor?:0,limit?:100}.
 * Cursors are byte offsets. Implicit log cursors are per manager instance;
 * explicit cursors also work after restart. Disk logs are UNBOUNDED and retained
 * until explicit cleanup. sudo/session/pty/pipefail are not silently emulated.
 */
function createJobManager({ runCommand, withSftp, readFrom, writeRemoteFile, resolveName, shq, wait = promise => promise, check = () => {} }) {
  const roots = new Map();
  const tasks = new Map();
  const queues = new Map();

  async function exec(host, command, timeoutMs = 10000) {
    const r = await runCommand(host, { command, timeoutMs });
    if (r.timedOut || (r.outcome && r.outcome !== 'completed') || r.exitCode == null) {
      throw jobError('JOB_OUTCOME_UNKNOWN', 'Remote operation outcome unknown; do not replay the launch');
    }
    if (r.exitCode !== 0) throw jobError('JOB_REMOTE_ERROR', r.stderr || `Remote operation exited ${r.exitCode}`);
    return r.stdout;
  }

  async function root(host) {
    if (!roots.has(host)) {
      const out = await exec(host, `bash -c ${shq('set -e; umask 077; cd -- "$HOME"; mkdir -p -- .cache/ssh-bridge/jobs; cd -- .cache/ssh-bridge/jobs; printf "SSH_BRIDGE_ROOT_V1\\0%s\\0" "$PWD"')}`);
      const match = out.match(/SSH_BRIDGE_ROOT_V1\0(\/[^\0]*)\0/);
      if (!match) throw jobError('JOB_PROTOCOL_ERROR', 'Could not discover per-user jobs directory');
      roots.set(host, match[1]);
    }
    return roots.get(host);
  }

  function descriptor(id) {
    if (typeof id !== 'string') throw jobError('JOB_INVALID_ID', 'task_id must be a string');
    const m = /^v1\.([A-Za-z0-9_-]+)\.([a-f0-9]{24})$/.exec(id);
    if (!m) throw jobError('JOB_INVALID_ID', 'Invalid managed task_id');
    const host = Buffer.from(m[1], 'base64url').toString('utf8');
    if (Buffer.from(host).toString('base64url') !== m[1] || resolveName(host) !== host) {
      throw jobError('JOB_INVALID_ID', 'task_id host is not a configured canonical host');
    }
    return { task_id: id, taskId: id, host };
  }

  async function text(host, file) {
    return withSftp(host, async s => {
      const r = await readFrom(s, file, 0, 16384);
      if (r.error) throw r.error;
      if (r.truncated || r.size > 16384) throw jobError('JOB_METADATA_ERROR', 'Job metadata exceeds limit');
      return r.content;
    });
  }

  async function load(id) {
    const desc = descriptor(id);
    if (tasks.get(id)?.cleaned) return tasks.get(id);
    const dir = `${await root(desc.host)}/${id}`;
    const meta = JSON.parse(await text(desc.host, `${dir}/metadata.json`));
    if (meta.version !== VERSION || meta.task_id !== id || meta.host !== desc.host) {
      throw jobError('JOB_METADATA_ERROR', 'Invalid or unsupported job metadata');
    }
    const task = Object.assign(tasks.get(id) || { cursor: 0 }, desc,
      { dir, createdAt: meta.createdAt, cwd: meta.cwd });
    tasks.set(id, task);
    return task;
  }

  function control(t, action, arg = '') {
    // Inline the controller for status/stop/cleanup: never execute a partial or
    // obsolete on-disk script after recovery. Only launch uses the uploaded copy.
    return `bash -c ${shq(CONTROL)} -- ${shq(action)} ${shq(t.dir)}${arg === '' ? '' : ` ${shq(String(arg))}`}`;
  }

  function parse(out) {
    const lines = out.split('\n').filter(x => x.startsWith(`${TAG}\t`));
    const m = lines.at(-1)?.split('\t');
    if (!m || !['running', 'starting', 'succeeded', 'failed', 'stopped', 'unknown'].includes(m[1]) ||
        !/^(?:-|[1-9][0-9]*)$/.test(m[2]) || !/^(?:-|[0-9]{1,3})$/.test(m[3])) {
      throw jobError('JOB_PROTOCOL_ERROR', 'Invalid job status response');
    }
    const status = m[1];
    return { status, pid: m[2] === '-' ? null : m[2], exitCode: m[3] === '-' ? null : Number(m[3]),
      running: status === 'running' || status === 'starting' ? true : TERMINAL.has(status) ? false : null };
  }

  async function status(t) {
    if (t.cleaned) return t.final;
    try { return parse(await exec(t.host, control(t, 'status'))); }
    catch (e) { return { status: 'unknown', running: null, exitCode: null, pid: null, error: e.message }; }
  }

  async function startBackground(name, args) {
    const { command, cwd, env = {}, input = '', sudo = false } = args || {};
    for (const key of Object.keys(args || {})) {
      if (!['host', 'command', 'cwd', 'env', 'input', 'sudo', 'timeoutMs', 'signal'].includes(key)) {
        throw jobError('JOB_UNSUPPORTED_OPTION', `Managed jobs do not support ${key}`);
      }
    }
    if (sudo !== false) throw jobError('JOB_UNSUPPORTED_OPTION', 'Managed sudo is unsupported; use an explicit noninteractive sudo command if appropriate');
    if (typeof command !== 'string' || !command.trim() || command.includes('\0') ||
        (cwd !== undefined && (typeof cwd !== 'string' || cwd.includes('\0'))) || typeof input !== 'string') {
      throw jobError('JOB_INVALID_ARGUMENT', 'command/cwd must be shell text without NUL; input must be a string');
    }
    if (!env || typeof env !== 'object' || Array.isArray(env)) throw jobError('JOB_INVALID_ARGUMENT', 'env must be an object');
    const exports = Object.entries(env).map(([key, value]) => {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || typeof value !== 'string' || value.includes('\0')) {
        throw jobError('JOB_INVALID_ARGUMENT', 'env requires valid variable names and string values without NUL');
      }
      return `export ${key}=${shq(value)}`;
    }).join('\n');
    const host = resolveName(name);
    const id = `v1.${Buffer.from(host).toString('base64url')}.${crypto.randomBytes(12).toString('hex')}`;
    const t = { ...descriptor(id), dir: `${await root(host)}/${id}`, cursor: 0, createdAt: new Date().toISOString() };
    const check = `set -e; for tool in bash setsid nohup mkdir mv ln rm sleep cat; do command -v "$tool" >/dev/null; done; test -r /proc/self/stat; test -r /proc/sys/kernel/random/boot_id; cd -- ${shq(cwd || '.')}; mkdir -m 700 -- ${shq(t.dir)}; : > ${shq(`${t.dir}/probe`)}; ln -- ${shq(`${t.dir}/probe`)} ${shq(`${t.dir}/probe.link`)}; rm -- ${shq(`${t.dir}/probe`)} ${shq(`${t.dir}/probe.link`)}`;
    await exec(host, `bash -c ${shq(check)}`);
    await withSftp(host, async s => {
      await writeRemoteFile(s, `${t.dir}/metadata.json`, JSON.stringify({ version: VERSION, task_id: id, host, createdAt: t.createdAt, cwd: cwd || null }));
      await writeRemoteFile(s, `${t.dir}/command.sh`, command);
      await writeRemoteFile(s, `${t.dir}/environment.sh`, `${exports}\n`);
      await writeRemoteFile(s, `${t.dir}/input`, input);
      await writeRemoteFile(s, `${t.dir}/output.log`, '');
      await writeRemoteFile(s, `${t.dir}/control.sh`, CONTROL);
    });
    tasks.set(id, t);
    try {
      const state = parse(await exec(host, control(t, 'launch', cwd || '.')));
      if (!state.pid) throw jobError('JOB_OUTCOME_UNKNOWN', 'Launch was not acknowledged');
      return { task_id: id, taskId: id, ...state, cursor: 0,
        logPolicy: 'Disk logs are unbounded; retained until explicit terminal cleanup.' };
    } catch (e) {
      // No automatic replay or cleanup: the supervisor may have started.
      throw Object.assign(e, { task_id: id, taskId: id, host, status: 'unknown' });
    }
  }

  // readFrom returns decoded text, which cannot repair UTF-8 split across reads.
  // Use bounded raw SFTP reads for logs; defer incomplete trailing code points by
  // leaving the cursor before them (also across restart/stateless polling).
  async function logs(t, cursor, limit, terminal) {
    return withSftp(t.host, async s => {
      const call = (method, ...args) => new Promise((resolve, reject) =>
        s[method](...args, (e, value) => e ? reject(e) : resolve(value)));
      const h = await call('open', `${t.dir}/output.log`, 'r');
      try {
        const st = await call('fstat', h);
        if (st.size < cursor) throw jobError('JOB_LOG_CHANGED', 'Log shrank below cursor');
        const buf = Buffer.alloc(limit + 1);
        let got = 0;
        while (got < buf.length) {
          let n;
          try { n = await call('read', h, buf, got, buf.length - got, cursor + got); }
          catch (e) { if (e.code === 1) break; throw e; }
          if (!Number.isInteger(n) || n < 0 || n > buf.length - got) throw jobError('JOB_PROTOCOL_ERROR', 'Invalid SFTP byte count');
          if (!n) break;
          got += n;
        }
        const truncated = got > limit;
        const count = Math.min(got, limit);
        const decoder = new StringDecoder('utf8');
        let content = decoder.write(buf.subarray(0, count));
        const pending = decoder.lastNeed ? decoder.lastTotal - decoder.lastNeed : 0;
        let consumed = count - pending;
        if (terminal && !truncated) { content += decoder.end(); consumed = count; }
        return { content, cursor: cursor + consumed, truncated };
      } finally { await call('close', h); }
    });
  }

  async function backgroundLogs(id, { cursor, limit = 65536 } = {}) {
    if (cursor !== undefined && (!Number.isSafeInteger(cursor) || cursor < 0)) throw jobError('JOB_INVALID_ARGUMENT', 'cursor must be a nonnegative byte offset');
    if (!Number.isInteger(limit) || limit < 4 || limit > MAX_LOG) throw jobError('JOB_INVALID_ARGUMENT', `limit must be 4..${MAX_LOG} bytes`);
    const previous = queues.get(id) || Promise.resolve();
    const result = previous.catch(() => {}).then(async () => {
      check();
      const t = await load(id);
      if (t.cleaned) throw jobError('JOB_CLEANED', 'Job artifacts were explicitly cleaned');
      const state = await status(t);
      const r = await logs(t, cursor ?? t.cursor, limit, TERMINAL.has(state.status));
      if (cursor === undefined) t.cursor = r.cursor;
      return { task_id: id, taskId: id, ...state, ...r };
    });
    queues.set(id, result);
    result.finally(() => { if (queues.get(id) === result) queues.delete(id); }).catch(() => {});
    return wait(result);
  }

  async function stopBackground(id, { graceMs = 2000, cleanup = false } = {}) {
    if (!Number.isInteger(graceMs) || graceMs < 0 || graceMs > 30000 || typeof cleanup !== 'boolean') {
      throw jobError('JOB_INVALID_ARGUMENT', 'graceMs must be 0..30000; cleanup must be boolean');
    }
    const t = await load(id);
    const state = t.cleaned ? t.final : parse(await exec(t.host, control(t, 'stop', Math.ceil(graceMs / 100)), graceMs + 15000));
    if (cleanup && !t.cleaned) {
      if (!TERMINAL.has(state.status)) throw jobError('JOB_NOT_TERMINAL', 'Cannot clean an active or unknown job');
      await exec(t.host, control(t, 'cleanup'));
      t.cleaned = true;
      t.final = state;
    }
    return { ok: TERMINAL.has(state.status), task_id: id, taskId: id, ...state, cleaned: !!t.cleaned };
  }

  async function listBackground(name, { cursor = 0, limit = 100 } = {}) {
    if (!Number.isSafeInteger(cursor) || cursor < 0 || !Number.isInteger(limit) || limit < 1 || limit > 200) {
      throw jobError('JOB_INVALID_ARGUMENT', 'list cursor must be nonnegative; limit must be 1..200');
    }
    const host = resolveName(name);
    try {
      const dir = await root(host);
      const pattern = `^v1\\.${Buffer.from(host).toString('base64url')}\\.[a-f0-9]{24}$`;
      const script = `n=0; for f in ${shq(dir)}/*/metadata.json; do [[ -f "$f" ]] || continue; x=@{f%/metadata.json}; x=@{x##*/}; [[ $x =~ ${pattern} ]] || continue; if ((n >= ${cursor} && n <= ${cursor + limit})); then printf '%s\\n' "$x"; fi; ((n+=1)); if ((n > ${cursor + limit})); then break; fi; done; :`.replaceAll('@{', '${');
      const out = await exec(host, `bash -c ${shq(script)}`);
      const ids = out.split('\n').filter(x => /^v1\.[A-Za-z0-9_-]+\.[a-f0-9]{24}$/.test(x));
      const jobs = [];
      for (const id of ids.slice(0, limit)) {
        try {
          if (descriptor(id).host !== host) continue;
          const t = await load(id);
          jobs.push({ task_id: id, taskId: id, host, createdAt: t.createdAt, cwd: t.cwd, ...await status(t) });
        } catch (e) { jobs.push({ task_id: id, taskId: id, host, status: 'unknown', running: null, exitCode: null, error: e.message }); }
      }
      return { host, status: jobs.some(t => t.status === 'unknown') ? 'unknown' : 'ok', jobs,
        cursor: cursor + Math.min(ids.length, limit), truncated: ids.length > limit };
    } catch (e) {
      return { host, status: 'unknown', jobs: [...tasks.values()].filter(t => t.host === host && !t.cleaned)
        .slice(cursor, cursor + limit).map(t => ({ task_id: t.task_id, taskId: t.taskId, host, status: 'unknown', running: null, exitCode: null })),
      cursor, truncated: false, error: e.message };
    }
  }

  return { startBackground, backgroundLogs, stopBackground, listBackground };
}

module.exports = { createJobManager };
