// Remote desktop capture. A screenshot is the one thing run_command cannot do
// well: the capture has to run inside the logged-in graphical session, which an
// SSH session's environment does not describe at all (no DISPLAY, no
// WAYLAND_DISPLAY, no D-Bus address), and the result is a binary image rather
// than text.
//
// What actually works was measured on Ubuntu 24.04 / GNOME 46 / Wayland:
//   - D-Bus org.gnome.Shell.Screenshot -> AccessDenied ("Screenshot is not
//     allowed"); GNOME 41+ restricts it to the seat's active local session.
//   - grim -> "compositor doesn't support wlr-screencopy-unstable-v1";
//     GNOME does not implement the wlroots protocol.
//   - import / scrot on Xwayland -> "unable to read X window image 'root'".
//   - gnome-screenshot with DISPLAY=:0 + the mutter Xwayland auth file ->
//     works (2358x1238 PNG).
// So the chain below prefers the tool that is known to work for the detected
// compositor, and still tries the others so a sway/KDE box works too.
//
// Every attempt is wrapped in `timeout`: gnome-screenshot falls back to X11 and
// then blocks forever when its D-Bus path fails, which would hang the tool call.

// Exit code meaning "there is no graphical session to capture". The script
// hard-codes 3; keep the two in sync (self-check asserts it).
const NO_SESSION = 3;

// Written to run under `bash -c` on the remote host with the output path as $1.
// Prints exactly one RESULT|... line on stdout; tool chatter is suppressed.
function buildCaptureScript() {
  return String.raw`
out="$1"
uid=$(id -u)
rt="/run/user/$uid"
me=$(id -un)

sess=""
stype=""
disp=""
# loginctl --value only exists from systemd 230; Ubuntu 16.04 ships 229, where
# it errors out and returns empty. Fall back to stripping the "Key=" prefix.
show_prop() {
  v=$(loginctl show-session "$1" -p "$2" 2>/dev/null)
  if [ "$v" = "$2=" ] || [ -z "$v" ]; then v=$(loginctl show-session "$1" -p "$2" --value 2>/dev/null); fi
  printf '%s' "$v" | cut -d= -f2-
}
# Prefer the user's own seat session: that is the one whose screen is on the
# physical display. A remote ssh session has Type=tty and no Display, so taking
# the first session for the user would pick the wrong one.
if command -v loginctl >/dev/null 2>&1; then
  for s in $(loginctl list-sessions --no-legend 2>/dev/null | awk -v u="$me" '$3==u {print $1}'); do
    t=$(show_prop "$s" Type)
    case "$t" in
      wayland|x11) sess="$s"; stype="$t"; disp=$(show_prop "$s" Display); break;;
    esac
  done
fi
if [ -z "$stype" ]; then stype="$XDG_SESSION_TYPE"; fi
if [ -z "$stype" ] && [ -n "$DISPLAY" ]; then stype="x11"; fi

if [ -z "$stype" ] || [ "$stype" = "tty" ]; then
  echo "RESULT|nosession|||"
  exit 3
fi

export XDG_RUNTIME_DIR="$rt"
[ -S "$rt/bus" ] && export DBUS_SESSION_BUS_ADDRESS="unix:path=$rt/bus"

errs=""
attempt() {
  name="$1"; shift
  rm -f "$out"
  timeout 20 "$@" >/dev/null 2>&1
  if [ -s "$out" ]; then
    echo "RESULT|ok|$name|$stype|$disp"
    exit 0
  fi
  errs="$errs$name; "
}
have() { command -v "$1" >/dev/null 2>&1; }

# The Xwayland auth file mutter writes is the only way to read :0 from outside
# the session; without it the X server refuses the connection outright.
xauth_file() {
  ls "$rt"/.mutter-Xwaylandauth.* 2>/dev/null | head -1
}

if [ "$stype" = "wayland" ]; then
  # GNOME: gnome-screenshot against Xwayland is the one path measured to work.
  xa=$(xauth_file)
  if [ -n "$xa" ] && have gnome-screenshot; then
    attempt gnome-screenshot-xwayland env DISPLAY=:0 XAUTHORITY="$xa" gnome-screenshot -f "$out"
  fi
  # wlroots / sway / KDE: native Wayland capture.
  if [ -z "$WAYLAND_DISPLAY" ]; then export WAYLAND_DISPLAY="wayland-0"; fi
  have grim && attempt grim grim "$out"
  have spectacle && attempt spectacle spectacle -b -n -o "$out"
  have gnome-screenshot && attempt gnome-screenshot gnome-screenshot -f "$out"
fi

# X11 (and Xwayland as a last resort on wayland).
xa=$(xauth_file)
[ -n "$xa" ] && export XAUTHORITY="$xa"
if [ -z "$DISPLAY" ]; then export DISPLAY="$disp"; fi
if [ -z "$DISPLAY" ]; then export DISPLAY=":0"; fi
have gnome-screenshot && attempt gnome-screenshot gnome-screenshot -f "$out"
have scrot && attempt scrot scrot -o "$out"
have maim && attempt maim maim "$out"
have import && attempt imagemagick import -window root "$out"
have xwd && have convert && attempt xwd bash -c "xwd -root -silent 2>/dev/null | convert xwd:- '$out' 2>/dev/null"

echo "RESULT|fail||$stype|$disp|$errs"
`;
}

// Parses the single RESULT line. Returns
// { ok, tool, sessionType, display, error, noSession }.
function parseCaptureResult(stdout) {
  const line = String(stdout || '')
    .split(/\r?\n/)
    .find((l) => l.startsWith('RESULT|'));
  if (!line) {
    return { ok: false, noSession: false, error: 'capture script produced no result line' };
  }
  const parts = line.split('|');
  const status = parts[1];
  const sessionType = parts[3] || '';
  const display = parts[4] || '';
  if (status === 'ok') return { ok: true, tool: parts[2] || '', sessionType, display };
  if (status === 'nosession') {
    return {
      ok: false,
      noSession: true,
      sessionType: '',
      display: '',
      error:
        'no graphical session detected on this host. Log in at the console (or start a display manager) ' +
        'and retry; a headless server has nothing to screenshot.',
    };
  }
  const failed = (parts[5] || '').trim();
  return {
    ok: false,
    noSession: false,
    sessionType,
    display,
    error:
      `no screenshot tool succeeded (session=${sessionType || 'unknown'}, display=${display || 'unknown'})` +
      (failed ? `; tried: ${failed}` : '') +
      '. GNOME/Wayland needs gnome-screenshot (D-Bus capture is restricted to the local session); ' +
      'wlroots/sway needs grim; X11 needs scrot or imagemagick.',
  };
}

// Verifies the captured file really is an image rather than an error page or a
// zero-filled placeholder: PNG/JPEG/GIF magic plus a non-trivial size.
function looksLikeImage(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 64) return false;
  const png = buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  const jpeg = buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff;
  const gif = buf.slice(0, 6).toString('ascii') === 'GIF8';
  return png || jpeg || gif;
}

// Optional downscale/re-encode. A full desktop capture is ~1.7 MB of PNG, which
// is a lot of context for an agent that only needs to read the layout; the same
// frame as a 1600px JPEG is ~30 KB and re-encodes in ~0.1 s. Best effort: if
// ImageMagick is missing the original capture is returned unchanged.
function buildOptimizeScript() {
  return String.raw`
set -u
src="$1"; dst="$2"; width="$3"; quality="$4"
if command -v convert >/dev/null 2>&1; then
  if convert "$src" -resize "$width"'x' -quality "$quality" "$dst" 2>/dev/null && [ -s "$dst" ]; then
    echo "OPTIMIZED"
    exit 0
  fi
fi
echo "ORIGINAL"
`;
}

module.exports = { buildCaptureScript, buildOptimizeScript, parseCaptureResult, looksLikeImage, NO_SESSION };
