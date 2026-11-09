// Persistent interactive shell over one SSH channel, with command boundaries
// taken from OSC 133 (FinalTerm shell integration) rather than an in-band
// sentinel.
//
// Why OSC 133 and not `echo SENTINEL:$?`: the sentinel is ordinary text mixed
// into the data stream, so anything that swallows stdin (sudo, ssh first-use,
// mysql -p) eats it and the call hangs until timeout; large output can push it
// out of a bounded buffer; and command output that happens to contain the
// sentinel forges a boundary. OSC 133 markers start with an ESC byte, so
// ordinary text cannot produce one by accident.
//
// The shell side is deliberately minimal: PROMPT_COMMAND prints D;<exit> and A
// before every prompt. There is no DEBUG trap, because it fires once per
// command *and* once per subshell, which produced duplicated/excessive markers
// in testing.

const OSC_MARK_RE = /\x1b\]133;([ABD])(?:;(\d+))?\x07/g;
// ANSI colour/CSI sequences a shell or tool may still emit.
const ANSI_RE = /\x1b\[[0-9;?]*[A-Za-z]/g;

// Shell startup. Written with backslash escapes so bash's printf produces the
// markers; a literal ESC byte in the source gets eaten by the PTY line editor.
function bootstrapScript() {
  return [
    // No prompt text: the markers carry all the structure we need, and a
    // decorative prompt would just be noise in the captured output.
    "PS1=''",
    // $? must be read into a variable first: anything earlier in the hook
    // overwrites it (a bare `printf ... "$?"` reported 0 for `false`).
    `PROMPT_COMMAND='rc=$?; printf "\\033]133;D;%s\\007\\033]133;A\\007" "$rc"'`,
    // The marker is echoed back as part of the command line too, so readiness
    // is signalled on a line of its own with a value that cannot appear in the
    // source we just sent.
    'printf "\\n__BRIDGE_READY_9f3a__\\n"',
  ].join('\n');
}

// True once the shell has actually run the whole bootstrap, not merely echoed
// it. The echoed source contains `__BRIDGE_READY...` inside a printf string, so
// require the token to appear at the start of a line.
function bootstrapDone(buf) {
  return /(^|\n)__BRIDGE_READY_9f3a__\r?\n/.test(buf);
}

// Splits a running buffer into completed commands.
// Returns { events: [{ exit, raw }], rest }.
//
// The stream looks like: <output> D;<exit> BEL A BEL <output> D;<exit> BEL A BEL
// So a D always closes the command whose output precedes it. The A that follows
// belongs to the *next* cycle and only tells us the shell is ready again.
function drainBuffer(buf) {
  const events = [];
  const marks = [];
  let m;
  OSC_MARK_RE.lastIndex = 0;
  while ((m = OSC_MARK_RE.exec(buf))) {
    marks.push({ kind: m[1], exit: m[2] === undefined ? null : Number(m[2]), start: m.index, end: OSC_MARK_RE.lastIndex });
  }
  let cursor = 0;
  let consumed = 0;
  for (const mk of marks) {
    if (mk.kind !== 'D') {
      if (mk.kind === 'A') consumed = Math.max(consumed, mk.end);
      continue;
    }
    const body = buf.slice(cursor, mk.start);
    events.push({ exit: mk.exit, raw: body });
    cursor = mk.end;
    consumed = mk.end;
    // Skip the A marker that immediately follows.
    const after = marks.find((x) => x.kind === 'A' && x.start >= mk.end);
    if (after) consumed = after.end;
  }
  return { events, rest: buf.slice(consumed) };
}

// Removes the echoed command line(s) and ANSI noise from a command's body.
// A multi-line command is echoed with a continuation prompt ("PS2", "> " by
// default) on every line after the first, so the whole echo block has to be
// dropped, not just one line.
function cleanOutput(raw, sentCommand) {
  let s = String(raw || '').replace(ANSI_RE, '').replace(/\r/g, '');
  if (sentCommand !== undefined) {
    const lines = String(sentCommand).split('\n').map((l) => l.trim());
    const out = s.split('\n');
    // Walk line by line while the echo still matches the command we sent,
    // allowing PS2's "> " prefix on continuations.
    let i = 0;
    for (; i < lines.length && i < out.length; i++) {
      const got = out[i].replace(/^>\s?/, '').trim();
      if (got !== lines[i]) break;
    }
    if (i > 0) s = out.slice(i).join('\n');
  }
  return s.replace(/^\n+/, '').replace(/\s+$/, '');
}

module.exports = { bootstrapScript, bootstrapDone, drainBuffer, cleanOutput, OSC_MARK_RE };
