// RFC 7692 permessage-deflate peer for NetGet's WebSocket tests: the `ws` npm package (Node's
// zlib), configured the way that stresses a deflate implementation most — a 10-bit window
// for the server's messages and no context takeover in either direction.
//
//   node ws_deflate.cjs <node_modules> client <port>   one JSON report on stdout
//   node ws_deflate.cjs <node_modules> server          {"ready":true,"port":N}, then
//                                                      {"message":...} lines; echoes "echo:"+text
const path = require('path');
const WebSocket = require(path.join(process.argv[2], 'ws'));

// The same 5000-letter LCG block the Rust tests and deflate_peer.py build. Repeated, its
// back-references are 5000 bytes long: past a 10- or 12-bit window.
function block(n = 5000) {
  let x = 1n;
  let out = '';
  for (let i = 0; i < n; i++) {
    x = (x * 1103515245n + 12345n) % 2147483648n;
    out += String.fromCharCode(97 + Number((x >> 16n) % 26n));
  }
  return out;
}
const LONG = block().repeat(3);

const deflate = {
  threshold: 0,
  serverNoContextTakeover: true,
  clientNoContextTakeover: true,
};

function emit(v) {
  process.stdout.write(JSON.stringify(v) + '\n');
}

if (process.argv[3] === 'client') {
  const ws = new WebSocket(`ws://127.0.0.1:${process.argv[4]}/deflate`, {
    perMessageDeflate: { ...deflate, serverMaxWindowBits: 10 },
  });
  const replies = [];
  const sends = [LONG, 'short and sweet', LONG];
  ws.on('open', () => ws.send(sends[0]));
  ws.on('message', (data, isBinary) => {
    replies.push(isBinary ? data.toString('hex') : data.toString());
    if (replies.length < sends.length) {
      ws.send(sends[replies.length]);
    } else {
      emit({ extensions: ws.extensions, replies });
      ws.close();
    }
  });
  ws.on('error', (e) => {
    emit({ error: String(e) });
    process.exit(1);
  });
  setTimeout(() => {
    emit({ timeout: true, extensions: ws.extensions, replies });
    process.exit(1);
  }, 15000).unref();
} else {
  const server = new WebSocket.WebSocketServer({ port: 0, host: '127.0.0.1', perMessageDeflate: deflate });
  server.on('listening', () => emit({ ready: true, port: server.address().port }));
  server.on('connection', (ws, req) => {
    emit({ offer: req.headers['sec-websocket-extensions'] || null, extensions: ws.extensions });
    ws.on('message', (data, isBinary) => {
      const text = isBinary ? data.toString('hex') : data.toString();
      emit({ message: text });
      ws.send(isBinary ? data : 'echo:' + text);
    });
  });
}
