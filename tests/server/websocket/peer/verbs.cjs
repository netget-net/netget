// Every verb NetGet's WebSocket server implements, driven by the `ws` npm package (its own
// framing, no compression). One JSON report on stdout; `real_client_test.rs` asserts on it.
//
//   node verbs.cjs <node_modules> <port>
//
// The same scenario as verbs.py, against the same handler.
const path = require('path');
const WebSocket = require(path.join(process.argv[2], 'ws'));
const base = `ws://127.0.0.1:${process.argv[3]}`;
const report = {};

function open(url, protocols) {
  const ws = new WebSocket(url, protocols, { perMessageDeflate: false });
  const inbox = [];
  const waiters = [];
  ws.on('message', (data, isBinary) => {
    const m = isBinary ? { binary: Buffer.from(data).toString('hex') } : data.toString();
    const w = waiters.shift();
    if (w) w(m);
    else inbox.push(m);
  });
  ws.next = () => new Promise((resolve) => {
    if (inbox.length) resolve(inbox.shift());
    else waiters.push(resolve);
  });
  ws.closed = new Promise((resolve) => ws.on('close', (code, reason) => resolve({ code, reason: reason.toString() })));
  return new Promise((resolve, reject) => {
    ws.on('open', () => resolve(ws));
    ws.on('unexpected-response', (req, res) => reject({ status: res.statusCode }));
    ws.on('error', (e) => reject({ error: String(e) }));
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  let ws = await open(base + '/session', ['v2.chat.example', 'chat']);
  report.subprotocol = ws.protocol;
  report.greeting = await ws.next();
  ws.send('héllo ✓');
  report.text = await ws.next();
  ws.send(Buffer.from([0x00, 0xff, 0xfe, 0x01, 0x80, 0x7f, 0xc3, 0x28]));
  report.binary = (await ws.next()).binary;
  // One text message in two frames: FIN clear, then a continuation with FIN set.
  ws.send('frag', { fin: false });
  ws.send('ment', { fin: true });
  report.fragmented = await ws.next();
  const pong = new Promise((resolve) => ws.once('pong', (data) => resolve(data.toString())));
  ws.ping('p1');
  report.pong = await pong;
  // Silent past the server's 2 s idle bound: ws answers the server's keepalive Ping itself.
  let pinged = 0;
  ws.on('ping', () => { pinged += 1; });
  await sleep(3000);
  report.server_pings = pinged;
  ws.send('after the keepalive');
  report.after_keepalive = await ws.next();
  ws.send('close please');
  report.server_close = await ws.closed;

  ws = await open(base + '/session');
  report.no_subprotocol = ws.protocol;
  await ws.next(); // the greeting
  ws.close(4001, 'bye');
  report.client_close_echo = await ws.closed;

  try {
    await open(base + '/reject');
    report.reject = 'opened';
  } catch (e) {
    report.reject = e.status !== undefined ? e.status : e;
  }
  process.stdout.write(JSON.stringify(report) + '\n');
  process.exit(0);
})().catch((e) => {
  process.stdout.write(JSON.stringify({ failed: String(e && e.stack ? e.stack : JSON.stringify(e)), report }) + '\n');
  process.exit(1);
});
setTimeout(() => {
  process.stdout.write(JSON.stringify({ timeout: true, report }) + '\n');
  process.exit(1);
}, 30000).unref();
