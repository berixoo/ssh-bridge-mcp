// Local TCP listeners pinned to one SSH transport; direct-tcpip uses no session slots.
const net = require('net');
const { randomUUID } = require('crypto');

function createTunnels({ runtime, resolveName }) {
  const tunnels = new Map();
  let stopped = false;
  const invalid = (message) => runtime.failure('INVALID_ARGUMENT', message);
  function check() {
    runtime.check();
    if (stopped) throw runtime.failure('CLOSED', 'tunnels are shut down');
  }
  function host(value, key) {
    if (typeof value !== 'string' || !value.length || value.length > 253 ||
      (!net.isIP(value) && !value.replace(/\.$/, '').split('.').every((label) => /^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$/.test(label)))) {
      throw invalid(`${key} must be a nonempty IP address or hostname`);
    }
    return value;
  }
  function port(value, key, minimum) {
    if (!Number.isInteger(value) || value < minimum || value > 65535) {
      throw invalid(`${key} must be an integer from ${minimum} to 65535`);
    }
    return value;
  }
  function nameOf(name) {
    if (name !== undefined && (typeof name !== 'string' || !name.trim())) throw invalid('host must be a nonempty string');
    return resolveName(name);
  }
  function describe(rec) {
    return { tunnel_id: rec.id, host: rec.name, local_host: rec.localHost, local_port: rec.localPort,
      remote_host: rec.remoteHost, remote_port: rec.remotePort };
  }
  function accept(rec, socket) {
    if (rec.closed || rec.entry.closing) { socket.destroy(); return; }
    let channel;
    let disposed = false;
    let answered = false;
    const dispose = () => {
      if (disposed) return;
      disposed = true;
      clearTimeout(timer);
      rec.peers.delete(dispose);
      if (channel) { socket.unpipe(channel); channel.unpipe(socket); }
      socket.destroy();
      channel?.destroy();
    };
    const timer = setTimeout(dispose, 15000);
    rec.peers.add(dispose);
    socket.on('error', dispose);
    socket.once('close', () => { dispose(); socket.removeListener('error', dispose); });
    try {
      rec.entry.client.forwardOut(socket.remoteAddress, socket.remotePort, rec.remoteHost, rec.remotePort, (err, stream) => {
        // A timed-out, disconnected or closed stream is never replayed on a new transport.
        if (answered || disposed || rec.closed || rec.entry.closing || err) {
          if (stream && stream !== channel) {
            const ignore = () => {};
            stream.on('error', ignore);
            stream.once('close', () => stream.removeListener('error', ignore));
            stream.destroy();
          }
          dispose();
          return;
        }
        answered = true;
        clearTimeout(timer);
        channel = stream;
        channel.on('error', dispose);
        channel.once('close', () => {
          // Normal EOF may leave writes buffered in the local socket; let them drain.
          if (!channel.readableEnded || !channel.writableFinished) dispose();
          channel.removeListener('error', dispose);
        });
        socket.pipe(channel).pipe(socket);
      });
    } catch (_) { dispose(); }
  }
  async function open(name, options = {}) {
    check();
    name = nameOf(name);
    if (!options || typeof options !== 'object' || Array.isArray(options)) throw invalid('tunnel options must be an object');
    const localHost = host(options.local_host === undefined ? '127.0.0.1' : options.local_host, 'local_host');
    const remoteHost = host(options.remote_host === undefined ? '127.0.0.1' : options.remote_host, 'remote_host');
    const localPort = port(options.local_port === undefined ? 0 : options.local_port, 'local_port', 0);
    const remotePort = port(options.remote_port, 'remote_port', 1);
    const entry = await runtime.wait(runtime.connection(name));
    check();
    if (entry.closing) throw runtime.failure('CONNECTION_CLOSED', 'SSH transport closed before tunnel opened');
    const rec = { id: randomUUID(), name, localHost, localPort, remoteHost, remotePort, entry,
      peers: new Set(), closed: false, ready: false };
    const server = net.createServer({ pauseOnConnect: true, allowHalfOpen: true }, (socket) => accept(rec, socket));
    let rejectReady;
    const listening = new Promise((resolve, reject) => {
      rejectReady = reject;
      server.once('listening', () => {
        if (rec.closed) { server.close(); return; }
        rec.localPort = server.address().port;
        rec.ready = true;
        resolve();
      });
    });
    // A synchronous listen failure must not leave this promise unobserved.
    listening.catch(() => {});
    rec.dispose = () => {
      if (rec.closed) return rec.done;
      rec.closed = true;
      tunnels.delete(rec.id);
      entry.owners.delete(rec.dispose);
      rejectReady(runtime.failure('TUNNEL_CLOSED', 'tunnel closed before listening'));
      for (const dispose of [...rec.peers]) dispose();
      rec.done = new Promise((resolve) => {
        // close also cancels a pending hostname lookup/listen in Node's net server.
        server.close(() => { server.removeAllListeners(); resolve(); });
      });
      return rec.done;
    };
    server.on('error', (err) => { rejectReady(err); rec.dispose(); });
    entry.owners.add(rec.dispose);
    tunnels.set(rec.id, rec);
    try {
      server.listen({ host: localHost, port: localPort, exclusive: true });
      await runtime.wait(listening, rec.dispose);
      check();
      if (rec.closed || entry.closing) throw runtime.failure('TUNNEL_CLOSED', 'tunnel closed during opening');
      return describe(rec);
    } catch (err) { rec.dispose(); throw err; }
  }
  function list(name) {
    check();
    const resolved = name === undefined ? undefined : nameOf(name);
    return [...tunnels.values()].filter((rec) => rec.ready && !rec.closed && (resolved === undefined || rec.name === resolved)).map(describe);
  }
  async function close(id) {
    if (typeof id !== 'string' || !id.trim()) throw invalid('tunnel_id must be a nonempty string');
    await tunnels.get(id)?.dispose();
    return { tunnel_id: id, closed: true };
  }
  async function shutdown() {
    stopped = true;
    await Promise.all([...tunnels.values()].map((rec) => rec.dispose()));
  }
  return { open, list, close, shutdown };
}

module.exports = { createTunnels };
