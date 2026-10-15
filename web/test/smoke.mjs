// Headless smoke test for the browser bundle, run under Node.
//
// Drives site/demo/pkg/netget_web.js the way the page does, minus the DOM: boots NetGet,
// checks the dashboard paints into the fake terminal, starts a TCP server through
// `start_server`, connects to it over the virtual network, sends a line, answers the
// model request the page receives with a `send_tcp_data` action, and asserts the bytes come
// back on the connection. Exit code 0 means the whole path — dashboard, ServerForm, virtual
// sockets, protocol server, LLM bridge, action executor — works in wasm.
//
// It then answers one more TCP request the way the page's "you are the model" composer
// (site/js/composer.js) does before anyone edits a field: the request's offered `actions`,
// the composer's default pick, every field prefilled from that action's example. That reply
// must be accepted and the example's bytes must reach the peer.
//
//   ./web/build.sh && node web/test/smoke.mjs
//
// Then HTTP, from the client side. `[ + http client ]` on an HTTP server card must resolve and
// connect — the same form the button applies (`connect_client_to_server`) — and an HTTP client
// started through `ClientForm` must complete real exchanges over the virtual loopback against
// NetGet's own `http` server: the model's answer to `http_connected` becomes a request, the
// server's model answers it, the response reaches the client and is reported back to the model,
// a request injected through the client's command channel (the dashboard's `[ send ]`) comes
// back `Executed` with its status, a non-200 is reported as a status, and `https://` is refused
// with the reason.
//
// Then the hyper servers, from outside NetGet: Node's own HTTP/1.1 client (`node:http`, llhttp)
// and HTTP/2 client (`node:http2`, nghttp2) are handed a Duplex over `NetGet.connect()` and talk
// to `http`, `openapi`, `jsonrpc` and `rss` (hyper's HTTP/1 server) and `http2` (h2c, the `h2`
// crate). Each request is answered by the model bridge, and each response is checked for its
// status, its headers, its body and — for the hyper servers — a `Date` header within a day of
// now. That last check is the point: hyper's HTTP/1 dispatcher reads the clock on its first
// poll, `SystemTime::now()` panics on wasm32-unknown-unknown, and until vendor/hyper patched the
// date cache to read `Date.now()` the first request to any hyper server killed the page. A
// panic anywhere fails the run by name (see `panics` below), not as a timeout.
//
// Then the other HTTP-family clients, which in the browser speak through the same transport
// (src/client/http_fetch) as the http client: jsonrpc and elasticsearch through `[ + client ]`
// on NetGet's own server of their protocol, `[ send ]`, and the response found parked on the
// client (`intercepts()`), since a dashboard-created client routes it to the human; openapi
// (which needs the server's spec, so it goes through ClientForm) and bitcoin (whose RPC NetGet
// serves only as plain HTTP) routed to the model, which runs the first request itself and is
// shown each response. An https:// jsonrpc endpoint is refused with the reason. npm, pypi,
// maven and torrent-tracker follow the button path too; the tracker's reply is bencoded with a
// binary compact peer list, which must arrive decoded, and an https:// npm registry is refused.
// http2's client follows the button path over h2c with prior knowledge (hyper's HTTP/2 client,
// its tasks on the shim's spawn), and the response must be read as HTTP/2. oauth2 and
// openidconnect hand the transport to their crates' own HTTP hook, routed to the model: a
// client-credentials token from NetGet's oauth2 server, and discovery, key set and token from
// its OpenID provider; an https:// token URL is refused. ollama follows the button path against
// NetGet's own Ollama server.
//
// The model's thinking: the TCP echo's reply carries a `reasoning` field, as the page sends a
// thinking model's `<think>` text, and it must reach the dashboard. Before any of that,
// site/js/thinking.js — the page's split of a streamed answer into the "Thinking…" block and
// the answer — is checked at each point of a `<think>` stream, and a model that does not think
// is checked to have nothing split out of its text.

import { checkRemainingHttpServers } from './remaining_http_servers.mjs';
import { readFileSync } from 'node:fs';
import { Duplex } from 'node:stream';
import http from 'node:http';
import http2 from 'node:http2';
import init, { NetGet } from '../../site/demo/pkg/netget_web.js';
import { offeredActions, defaultActionIndex, newEntry, buildReply, buildAction } from '../../site/js/composer.js';
import { splitThinking } from '../../site/js/thinking.js';

// A Rust panic in the bundle is written by console_error_panic_hook and then aborts the wasm
// instance (`RuntimeError: unreachable`), after which every later call into it throws. Record
// either, so a waiting step fails naming the panic rather than timing out behind it.
const panics = [];
const consoleError = console.error.bind(console);
console.error = (...args) => {
    const text = args.map((a) => (a && a.stack) || String(a)).join(' ');
    if (/panicked at|RuntimeError/.test(text)) panics.push(text);
    consoleError(...args);
};
process.on('uncaughtException', (e) => { panics.push((e && e.stack) || String(e)); fail('uncaught exception: ' + ((e && e.stack) || e)); });
process.on('unhandledRejection', (e) => { panics.push((e && e.stack) || String(e)); fail('unhandled rejection: ' + ((e && e.stack) || e)); });

const wasm = readFileSync(new URL('../../site/demo/pkg/netget_web_bg.wasm', import.meta.url));
await init({ module_or_path: wasm });

const dec = new TextDecoder();
const enc = new TextEncoder();
let screen = '';
const requests = [];
const received = [];
// When set, requests are answered by the composer's default reply instead of the echo below.
let answerLikeTheComposer = false;
const composed = [];
// What the HTTP client reported to the model: its connect event and each response it read.
const httpConnected = [];
const httpResponses = [];
// Every request a hyper server reported to the model: { protocol, context }.
const serverRequests = [];
// What the model-routed HTTP-family clients reported to the model, by protocol: each
// response event's data.
const clientResponses = { openapi: [], bitcoin: [], oauth2: [], oidc: [] };

function fail(msg) {
    console.error('FAIL:', msg);
    console.error('--- last terminal output ---');
    console.error(screen.slice(-2000));
    process.exit(1);
}

function waitFor(pred, what, ms = 15000) {
    const deadline = Date.now() + ms;
    return new Promise((resolve, reject) => {
        const tick = () => {
            if (panics.length) return reject(new Error('the wasm instance panicked while waiting for ' + what + ':\n' + panics.join('\n')));
            if (pred()) return resolve();
            if (Date.now() > deadline) return reject(new Error('timed out waiting for ' + what));
            setTimeout(tick, 50);
        };
        tick();
    });
}

const PORT = 7000;
const OIDC_PORT = 8091;  // the OpenID provider, which names itself in its discovery document
const SMOKE_REASONING = 'smokethought: the peer wants its line shouted back';  // a <think> block's text

// site/js/thinking.js, at each point of a stream.
function checkThinkingSplit() {
    const same = (got, want, what) => {
        if (JSON.stringify(got) !== JSON.stringify(want)) fail(`thinking.js: ${what}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    };
    const pick = (s) => ({ thinking: s.thinking, answer: s.answer, done: s.thinkingDone });
    const answer = '{"actions":[{"type":"send_telnet_line","line":"hi"}]}';
    const think = '<think>\nThey said hi.\nGreet them.\n</think>\n\n' + answer;
    same(pick(splitThinking('<thi', { thinks: true })), { thinking: '', answer: '', done: false }, 'a think tag opening');
    same(pick(splitThinking(think.slice(0, 22), { thinks: true })), { thinking: 'They said hi.', answer: '', done: false }, 'mid-thought');
    same(splitThinking(think.slice(0, think.indexOf('</think>') + 4), { thinks: true }).thinking, 'They said hi.\nGreet them.', 'a closing tag half written');
    same(pick(splitThinking(think.slice(0, think.indexOf('</think>') + 12), { thinks: true })), { thinking: 'They said hi.\nGreet them.', answer: '{"', done: true }, 'the answer begun');
    same(pick(splitThinking(think, { thinks: true, final: true })), { thinking: 'They said hi.\nGreet them.', answer, done: true }, 'the whole answer');
    // A template that opened the block in the prompt: only the closing tag is written.
    same(splitThinking('Hmm.\n</think>\n{"actions":[]}', { thinks: true, final: true }).answer, '{"actions":[]}', 'no opening tag');
    same(splitThinking('Hmm, still', { thinks: true }).thinking, 'Hmm, still', 'a thinking model before its closing tag');
    // Thinking switched off (`enable_thinking: false` prefills an empty block), or skipped.
    same(pick(splitThinking('<think>\n\n</think>\n\n' + answer, { thinks: true, final: true })), { thinking: '', answer, done: true }, 'an empty think block');
    same(splitThinking(answer.slice(0, 9), { thinks: true }).answer, answer.slice(0, 9), 'a thinking model answering directly');
    same(splitThinking('plain words', { thinks: true, final: true }).answer, 'plain words', 'unterminated, untagged text at the end is the answer');
    same(pick(splitThinking('<think>out of tokens', { thinks: true, final: true })), { thinking: 'out of tokens', answer: '', done: true }, 'a think block that never closed');
    // A model that does not think: nothing is split out, whatever the text holds.
    same(pick(splitThinking(think.slice(0, 30))), { thinking: '', answer: think.slice(0, 30), done: true }, 'a model that does not think');
}

const netget = new NetGet({
    cols: 120,
    rows: 36,
    model: 'smoke-test',
    theme: 'dark',
    log: 'warn',
    onOutput: (bytes) => { screen += dec.decode(bytes); },
    onLlm: async (json) => {
        const req = JSON.parse(json);
        requests.push(req);
        if (answerLikeTheComposer) {
            const actions = offeredActions(req);
            const entry = actions.length ? newEntry(actions[defaultActionIndex(actions)]) : null;
            const built = entry ? buildReply(req, actions, [entry]) : { ok: false };
            composed.push({ req, actions, entry, built });
            return JSON.stringify(built.ok ? built.reply : { error: 'the composer could not build a reply' });
        }
        // The network-event path sends one flattened prompt whose user turn carries
        // "Context data:\n{...}" with the connection id and the received text.
        const user = req.messages.find((m) => m.role === 'user') || req.messages[req.messages.length - 1];
        const ctx = user.content.indexOf('Context data:');
        let context = {};
        if (ctx >= 0) {
            try { context = JSON.parse(user.content.slice(ctx + 'Context data:'.length)); } catch (e) { /* prompt-only */ }
        }
        // A client's prompt carries its event as "Event: <id>\nData: {...}" instead.
        const withEvent = req.messages.map((m) => m.content).find((c) => c.includes('\nData: {'));
        if (ctx < 0 && withEvent) {
            try { context = JSON.parse(withEvent.slice(withEvent.lastIndexOf('\nData: ') + '\nData: '.length)); } catch (e) { /* prompt-only */ }
        }
        const offered = new Set((req.actions || []).map((a) => a.name));
        const answer = (actions) => JSON.stringify({ content: JSON.stringify({ actions }), prompt_tokens: 10, completion_tokens: 5 });
        // The hyper servers. Each answer is built from the request the server reported, so a
        // response that reaches the client proves the request's fields reached the model.
        if (offered.has('send_http_response')) {
            serverRequests.push({ protocol: 'http', context });
            if (context.path === '/hello.txt') {
                return answer([{ type: 'send_http_response', status: 200, headers: { 'Content-Type': 'text/plain' }, body: 'hello from the http server' }]);
            }
            if (context.method === 'POST' && context.path === '/echo') {
                return answer([{ type: 'send_http_response', status: 201, headers: { 'Content-Type': 'text/plain', 'X-Smoke': 'echoed' }, body: String(context.body).toUpperCase() }]);
            }
            // Bitcoin Core's RPC is JSON-RPC 1.0 over HTTP POST; NetGet has no server of it
            // (its `bitcoin` server speaks the P2P wire protocol), so the http server answers
            // the shape bitcoind would.
            if (context.method === 'POST' && String(context.body).includes('"jsonrpc":"1.0"')) {
                const call = JSON.parse(context.body);
                return answer([{ type: 'send_http_response', status: 200, headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ result: { chain: 'regtest', blocks: 101, called: call.method }, error: null, id: call.id }) }]);
            }
            if (context.path === '/') {
                return answer([{ type: 'send_http_response', status: 200, headers: { 'Content-Type': 'text/html' }, body: '<h1>smoke</h1><p>accept=' + (context.headers || {}).accept + '</p>' }]);
            }
            return answer([{ type: 'send_http_response', status: 404, headers: { 'Content-Type': 'text/plain' }, body: 'no such page: ' + context.path }]);
        }
        if (offered.has('send_openapi_response')) {
            serverRequests.push({ protocol: 'openapi', context });
            return answer([{ type: 'send_openapi_response', status_code: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify([{ id: 1, title: 'Buy milk', path: context.path }]) }]);
        }
        if (offered.has('jsonrpc_success')) {
            serverRequests.push({ protocol: 'jsonrpc', context });
            if (context.method === 'add' && Array.isArray(context.params)) {
                return answer([{ type: 'jsonrpc_success', result: context.params.reduce((a, b) => a + b, 0) }]);
            }
            return answer([{ type: 'jsonrpc_error', code: -32601, message: 'Method not found: ' + context.method }]);
        }
        if (offered.has('generate_rss_feed')) {
            serverRequests.push({ protocol: 'rss', context });
            return answer([{ type: 'generate_rss_feed', title: 'Smoke News', link: 'http://127.0.0.1/news.xml', description: 'Served from ' + context.path,
                items: [{ title: 'First post', link: 'http://127.0.0.1/1', description: 'Hello from the browser build' }] }]);
        }
        if (offered.has('send_http2_response')) {
            serverRequests.push({ protocol: 'http2', context });
            return answer([{ type: 'send_http2_response', status: 200, headers: { 'content-type': 'text/plain', 'x-smoke': 'h2' }, body: 'h2 says hi to ' + context.uri }]);
        }
        // NetGet's OAuth2 authorization server: a token for whatever grant was asked.
        if (offered.has('oauth2_token_response')) {
            serverRequests.push({ protocol: 'oauth2', context });
            return answer([{ type: 'oauth2_token_response', access_token: 'smoke-oauth2-token', token_type: 'Bearer', expires_in: 1234, scope: 'read smoke' }]);
        }
        // NetGet's OpenID provider: discovery naming itself, an empty key set, a token.
        if (offered.has('send_discovery_document')) {
            serverRequests.push({ protocol: 'openid', context });
            const base = 'http://127.0.0.1:' + OIDC_PORT;
            if (context.endpoint_type === 'discovery') {
                return answer([{ type: 'send_discovery_document', issuer: base, authorization_endpoint: base + '/authorize', token_endpoint: base + '/token',
                    userinfo_endpoint: base + '/userinfo', jwks_uri: base + '/jwks.json', supported_scopes: ['openid', 'smoke'] }]);
            }
            if (context.endpoint_type === 'jwks') return answer([{ type: 'send_jwks_response', keys: [] }]);
            if (context.endpoint_type === 'token') return answer([{ type: 'send_token_response', access_token: 'smoke-oidc-token', token_type: 'Bearer', expires_in: 4321 }]);
            return answer([{ type: 'send_error_response', error: 'invalid_request', error_description: 'not in the smoke test' }]);
        }
        if (offered.has('ollama_generate_response')) {
            serverRequests.push({ protocol: 'ollama', context });
            return answer([{ type: 'ollama_generate_response', response_text: 'Smoke City, said ' + context.model }]);
        }
        if (offered.has('npm_package_metadata')) {
            serverRequests.push({ protocol: 'npm', context });
            const name = decodeURIComponent(String(context.path).replace(/^\//, ''));
            return answer([{ type: 'npm_package_metadata', metadata: { name, description: 'served to the smoke test', 'dist-tags': { latest: '1.3.0' },
                versions: { '1.3.0': { name, version: '1.3.0', dist: { tarball: `http://127.0.0.1/${name}/-/${name}-1.3.0.tgz` } } } } }]);
        }
        if (offered.has('send_pypi_response')) {
            serverRequests.push({ protocol: 'pypi', context });
            return answer([{ type: 'send_pypi_response', status: 200, headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ info: { name: 'smoke-pkg', version: '2.0.0', summary: 'served to the smoke test from ' + context.path }, releases: { '2.0.0': [] }, urls: [] }) }]);
        }
        if (offered.has('send_maven_artifact')) {
            serverRequests.push({ protocol: 'maven', context });
            return answer([{ type: 'send_maven_artifact', status: 200, content_type: 'application/xml',
                body: `<?xml version="1.0" encoding="UTF-8"?>\n<project><modelVersion>4.0.0</modelVersion><groupId>${context.group_id}</groupId><artifactId>${context.artifact_id}</artifactId><version>${context.version}</version><name>smoke pom</name></project>\n` }]);
        }
        if (offered.has('send_announce_response')) {
            serverRequests.push({ protocol: 'torrent-tracker', context });
            return answer([{ type: 'send_announce_response', interval: 900, complete: 3, incomplete: 1, compact: 1, peers: [{ ip: '127.0.0.1', port: 6881 }, { ip: '10.0.0.2', port: 51413 }] }]);
        }
        if (offered.has('send_elasticsearch_response')) {
            serverRequests.push({ protocol: 'elasticsearch', context });
            return answer([{ type: 'send_elasticsearch_response', status_code: 200,
                body: JSON.stringify({ took: 1, timed_out: false, hits: { total: { value: 1, relation: 'eq' },
                    hits: [{ _index: context.index, _id: 'dune', _source: { title: 'Dune', asked: context.operation } }] } }) }]);
        }
        // The OAuth2 client: ask for a client-credentials token when connected; report tokens.
        if (offered.has('generate_auth_url')) {
            if (context.access_token !== undefined || context.error !== undefined) {
                clientResponses.oauth2.push(context);
                return answer([]);
            }
            return answer([{ type: 'exchange_client_credentials', scopes: 'read smoke' }]);
        }
        // The OpenID Connect client: after discovery, a client-credentials token; report it.
        if (offered.has('discover_configuration')) {
            if (context.access_token !== undefined) {
                clientResponses.oidc.push(context);
                return answer([]);
            }
            if (context.issuer !== undefined) {
                clientResponses.oidc.push(context);
                return answer([{ type: 'exchange_client_credentials', scopes: 'openid' }]);
            }
            return answer([]);
        }
        // The OpenAPI client: run the spec's operation when connected, report its response.
        if (offered.has('execute_operation')) {
            if (context.status_code !== undefined) {
                clientResponses.openapi.push(context);
                return answer([]);
            }
            if (context.operations !== undefined) {
                return answer([{ type: 'execute_operation', operation_id: 'listTodos', path_params: {}, query_params: { owner: 'smoke test' } }]);
            }
        }
        // The Bitcoin RPC client: nothing on connect; report every response.
        if (offered.has('get_blockchain_info')) {
            if (context.status_code !== undefined) clientResponses.bitcoin.push(context);
            return answer([]);
        }
        // The HTTP client: fetch a page when connected, and report every response.
        if (offered.has('send_http_request')) {
            if (context.status_code !== undefined) {
                httpResponses.push(context);
                return answer([]);
            }
            if (context.base_url !== undefined) {
                httpConnected.push(context);
                return answer([{ type: 'send_http_request', method: 'GET', path: '/hello.txt' }]);
            }
        }
        const text = String(context.data ?? context.data_preview ?? context.content ?? context.text ?? '');
        // Answer in the vocabulary of whichever server asked: TCP echoes uppercased, UDP
        // reverses.
        const isUdp = req.messages.some((m) => m.content.includes('send_udp_response'));
        if (isUdp) {
            const reply = { actions: [{ type: 'send_udp_response', data: [...text.trim()].reverse().join(''), encoding: 'text' }] };
            return JSON.stringify({ content: JSON.stringify(reply), prompt_tokens: 10, completion_tokens: 5 });
        }
        const reply = { actions: [{ type: 'send_tcp_data', data: text.toUpperCase() }] };
        return JSON.stringify({ content: JSON.stringify(reply), reasoning: SMOKE_REASONING, prompt_tokens: 10, completion_tokens: 5 });
    },
});

// An OpenAPI document with one route, for the openapi server's `spec` startup parameter.
const TODO_SPEC = `openapi: 3.1.0
info:
  title: Todo API
  version: 1.0.0
paths:
  /todos:
    get:
      operationId: listTodos
      responses:
        '200':
          description: the todo list
`;

// Start a server through the page's start_server and wait until its port listens.
async function startServer(spec) {
    let started = null;
    netget.start_server(JSON.stringify(spec), (json) => { started = JSON.parse(json); });
    await waitFor(() => started !== null, `start_server (${spec.protocol}) to answer`);
    if (started.error) fail(`start_server ${spec.protocol}: ` + started.error);
    await waitFor(() => netget.listening_ports().includes(spec.port), `${spec.protocol} to listen on ${spec.port}`);
    return started;
}

// A Node Duplex over one virtual-loopback connection, for Node's own HTTP clients.
function virtualSocket(port) {
    let id = null;
    const sock = new Duplex({
        read() {},
        write(chunk, _encoding, callback) {
            callback(netget.send(id, chunk) ? null : new Error(`the virtual connection to :${port} is gone`));
        },
        destroy(err, callback) {
            if (id !== null) netget.close(id);
            callback(err);
        },
    });
    id = netget.connect(port, (bytes) => sock.push(Buffer.from(bytes)), () => sock.push(null));
    return sock;
}

// One HTTP/1.1 exchange through node:http over the virtual loopback.
function httpRequest(port, { method = 'GET', path = '/', headers = {}, body } = {}) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => { req.destroy(new Error(`no response to ${method} ${path} on :${port} within 20s`)); }, 20000);
        const req = http.request({ host: '127.0.0.1', port, method, path, headers, createConnection: () => virtualSocket(port) }, (res) => {
            const chunks = [];
            res.on('data', (c) => chunks.push(c));
            res.on('end', () => { clearTimeout(timer); resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }); });
            res.on('error', (e) => { clearTimeout(timer); reject(e); });
        });
        req.on('error', (e) => { clearTimeout(timer); reject(new Error(`${method} ${path} on :${port}: ${e.message}`)); });
        if (body !== undefined) req.write(body);
        req.end();
    });
}

// One HTTP/2 exchange (prior-knowledge h2c) through node:http2 over the virtual loopback.
function http2Request(port, path) {
    return new Promise((resolve, reject) => {
        const session = http2.connect(`http://127.0.0.1:${port}`, { createConnection: () => virtualSocket(port) });
        const timer = setTimeout(() => { session.destroy(new Error(`no HTTP/2 response to ${path} on :${port} within 20s`)); }, 20000);
        const done = (err, value) => { clearTimeout(timer); session.close(); err ? reject(err) : resolve(value); };
        session.on('error', (e) => done(new Error(`h2 session to :${port}: ${e.message}`)));
        const stream = session.request({ ':method': 'GET', ':path': path });
        let headers = null;
        const chunks = [];
        stream.on('response', (h) => { headers = h; });
        stream.on('data', (c) => chunks.push(c));
        stream.on('end', () => done(null, { status: headers && headers[':status'], headers: headers || {}, body: Buffer.concat(chunks).toString('utf8') }));
        stream.on('error', (e) => done(new Error(`h2 stream ${path} on :${port}: ${e.message}`)));
        stream.end();
    });
}

// A hyper server's Date header: present, an HTTP date, and today's — the clock the vendored
// hyper reads on wasm32 is the page's, not a placeholder.
const dates = [];
function checkDate(value, what) {
    if (!value) fail(what + ': no Date header');
    const at = Date.parse(value);
    if (!/^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(value) || Number.isNaN(at)) fail(what + ': Date is not an HTTP date: ' + JSON.stringify(value));
    if (Math.abs(at - Date.now()) > 24 * 3600 * 1000) fail(what + ': Date is not today: ' + value);
    dates.push(value);
}

try {
    checkThinkingSplit();
    await waitFor(() => screen.length > 500, 'the dashboard to paint');
    if (!/\x1b\[\d+;\d+H/.test(screen)) fail('output has no cursor-positioning sequences; not a rendered frame');

    let started = null;
    netget.start_server(JSON.stringify({
        protocol: 'tcp', port: PORT,
        instruction: 'Echo every line back to the client, uppercased.',
    }), (json) => { started = JSON.parse(json); });
    await waitFor(() => started !== null, 'start_server to answer');
    if (started.error) fail('start_server: ' + started.error);

    await waitFor(() => netget.listening_ports().includes(PORT), `port ${PORT} to be listening`);

    let servers = null;
    netget.servers((json) => { servers = JSON.parse(json); });
    await waitFor(() => servers !== null, 'servers()');
    if (!servers.some((s) => s.protocol === 'tcp' && s.port === PORT)) fail('servers() does not list the tcp server: ' + JSON.stringify(servers));

    let closed = null;
    const conn = netget.connect(PORT, (bytes) => received.push(dec.decode(bytes)), (reason) => { closed = reason ?? 'eof'; });
    if (!netget.send(conn, enc.encode('hello netget\n'))) fail('send() reported the connection is gone');

    await waitFor(() => requests.length > 0, 'the LLM request', 20000);
    const req = requests[0];
    if (req.kind !== 'generate') fail('expected a generate request, got ' + req.kind);
    if (!req.messages.some((m) => m.content.includes('hello netget'))) fail('the prompt does not carry the received bytes');

    await waitFor(() => received.join('').includes('HELLO NETGET'), 'the echoed bytes', 20000);
    // The reply's thinking reached the dashboard (its stream column).
    await waitFor(() => screen.includes('smokethought'), 'the model thinking on the dashboard', 10000);

    // The dashboard should have repainted with the server card by now.
    await waitFor(() => /tcp/i.test(screen.slice(-20000)), 'the tcp card on screen');

    // The page switches who answers with set_model: the next request names that model.
    netget.set_models(JSON.stringify(['smoke-test', 'smoke-switched']));
    netget.set_model('smoke-switched');

    netget.close(conn);

    // The composer: answer a fresh TCP request with its default, example-prefilled action.
    answerLikeTheComposer = true;
    const composerReceived = [];
    const conn2 = netget.connect(PORT, (bytes) => composerReceived.push(dec.decode(bytes)), () => {});
    if (!netget.send(conn2, enc.encode('compose me\n'))) fail('send() on the composer connection failed');
    await waitFor(() => composed.length > 0, 'the composer-answered request', 20000);
    const c = composed[0];
    if (!c.actions.length) fail('the request offers no actions: ' + JSON.stringify(Object.keys(c.req)));
    if (!c.actions.some((a) => a.example && typeof a.example === 'object' && Object.keys(a.example).length)) fail('no offered action carries an example');
    if (!c.actions.every((a) => Array.isArray(a.parameters))) fail('an offered action has no parameter list');
    if (c.req.model !== 'smoke-switched') fail('set_model did not reach the request: model is ' + JSON.stringify(c.req.model));
    if (c.entry.name !== 'send_tcp_data') fail('the composer would preselect ' + c.entry.name + ', not send_tcp_data; offered: ' + c.actions.map((a) => a.name).join(', '));
    if (!c.built.ok) fail('the composer could not build a reply from the example: ' + JSON.stringify(c.built.errors));
    const sent = buildAction(c.entry).value;
    const example = c.actions.find((a) => a.name === 'send_tcp_data').example;
    if (JSON.stringify(sent) !== JSON.stringify(example)) fail('the prefilled action differs from its example: ' + JSON.stringify(sent) + ' vs ' + JSON.stringify(example));
    await waitFor(() => composerReceived.join('') === sent.data, 'the example bytes (' + JSON.stringify(sent.data) + ') on the wire', 20000);
    answerLikeTheComposer = false;
    netget.close(conn2);

    // UDP: a datagram server on the virtual network, a page-side socket, one round trip.
    const UDP_PORT = 5555;
    let udpStarted = null;
    netget.start_server(JSON.stringify({
        protocol: 'udp', port: UDP_PORT,
        instruction: 'Reply to every datagram with its text reversed.',
    }), (json) => { udpStarted = JSON.parse(json); });
    await waitFor(() => udpStarted !== null, 'start_server (udp) to answer');
    if (udpStarted.error) fail('start_server udp: ' + udpStarted.error);
    await waitFor(() => Array.from(netget.bound_udp_ports()).includes(UDP_PORT), `udp port ${UDP_PORT} to be bound`);

    const datagrams = [];
    const sock = netget.udp_open((bytes, fromPort) => datagrams.push([dec.decode(bytes), fromPort]));
    const before = requests.length;
    if (!netget.udp_send(sock, UDP_PORT, enc.encode('abc'))) fail('udp_send() reported the socket is gone');
    await waitFor(() => requests.length > before, 'the UDP model request', 20000);
    await waitFor(() => datagrams.some(([t]) => t.includes('cba')), 'the reversed datagram', 20000);
    if (datagrams[0][1] !== UDP_PORT) fail('reply came from port ' + datagrams[0][1] + ', expected ' + UDP_PORT);
    netget.udp_close(sock);

    // HTTP, the button: an http server's card offers [ + http client ], and pressing it (the
    // same form, through connect_client_to_server) connects a client to it.
    const HTTP_PORT = 8080;
    let httpStarted = null;
    netget.start_server(JSON.stringify({ protocol: 'http', port: HTTP_PORT, instruction: 'Serve a tiny site.' }), (json) => { httpStarted = JSON.parse(json); });
    await waitFor(() => httpStarted !== null, 'start_server (http) to answer');
    if (httpStarted.error) fail('start_server http: ' + httpStarted.error);
    await waitFor(() => netget.listening_ports().includes(HTTP_PORT), `port ${HTTP_PORT} to be listening`);
    // Tall enough that every card, with its open peers section, is on screen at once.
    netget.resize(160, 200);
    const screenBefore = screen.length;
    await waitFor(() => screen.slice(screenBefore).includes('+ http client'), 'the [ + http client ] button on the http card');
    let viaButton = null;
    netget.connect_client_to_server(httpStarted.id, (json) => { viaButton = JSON.parse(json); });
    await waitFor(() => viaButton !== null, 'connect_client_to_server to answer');
    if (viaButton.error) fail('[ + http client ]: ' + viaButton.error);
    if (viaButton.protocol !== 'HTTP' || viaButton.remote_addr !== `127.0.0.1:${HTTP_PORT}`) fail('[ + http client ] made the wrong client: ' + JSON.stringify(viaButton));
    let clients = null;
    netget.clients((json) => { clients = JSON.parse(json); });
    await waitFor(() => clients !== null, 'clients()');
    const buttonClient = clients.find((c) => c.id === viaButton.id);
    if (!buttonClient || buttonClient.status !== 'Connected') fail('the [ + http client ] client is not connected: ' + JSON.stringify(clients));

    // HTTP, the exchanges: NetGet's HTTP client against NetGet's own hyper-based http server,
    // both driven by the model bridge.
    let refused = null;
    netget.start_client(JSON.stringify({ protocol: 'http', remote_addr: `https://127.0.0.1:${HTTP_PORT}`, instruction: 'Fetch /hello.txt.' }), (json) => { refused = JSON.parse(json); });
    await waitFor(() => refused !== null, 'start_client (https) to answer');
    if (!refused.error || !refused.error.includes('https:// is not available')) fail('an https:// client was not refused with the reason: ' + JSON.stringify(refused));

    let httpClient = null;
    netget.start_client(JSON.stringify({ protocol: 'http', remote_addr: `127.0.0.1:${HTTP_PORT}`, instruction: 'Fetch /hello.txt and read it.' }), (json) => { httpClient = JSON.parse(json); });
    await waitFor(() => httpClient !== null, 'start_client (http) to answer');
    if (httpClient.error) fail('start_client http: ' + httpClient.error);
    await waitFor(() => httpConnected.length > 0, 'the http_connected model request', 20000);
    await waitFor(() => httpResponses.length > 0, 'the /hello.txt response reported to the model', 20000);
    const first = httpResponses[0];
    if (first.status_code !== 200) fail('/hello.txt came back ' + JSON.stringify(first));
    if (String(first.body) !== 'hello from the http server') fail('the http server\'s body did not reach the client: ' + JSON.stringify(first));
    const headerOf = (headers, name) => Object.entries(headers || {}).find(([k]) => k.toLowerCase() === name)?.[1];
    if (headerOf(first.headers, 'content-type') !== 'text/plain') fail('the response headers did not reach the client: ' + JSON.stringify(first.headers));
    checkDate(headerOf(first.headers, 'date'), 'the http server, read by NetGet\'s http client');

    // The dashboard's [ send ] on that client, and a status that is not 200.
    let injected = null;
    netget.send_to_client(httpClient.id, JSON.stringify({ type: 'send_http_request', method: 'GET', path: '/missing' }), (json) => { injected = JSON.parse(json); });
    await waitFor(() => injected !== null, 'send_to_client to answer', 45000);
    const detail = injected.Executed && injected.Executed.detail;
    if (!detail || !detail.includes('GET /missing -> 404')) fail('send_to_client did not report the exchange: ' + JSON.stringify(injected));
    await waitFor(() => httpResponses.length > 1, 'the injected request\'s response reported to the model', 20000);
    if (httpResponses[1].status_code !== 404 || !String(httpResponses[1].body).includes('no such page: /missing')) fail('the 404 did not reach the client intact: ' + JSON.stringify(httpResponses[1]));

    // The hyper servers, spoken to by Node's own HTTP clients over the virtual loopback.
    const hyper = {};

    // http: a GET and a POST with a body, through node:http (llhttp).
    const root = await httpRequest(HTTP_PORT, { path: '/', headers: { accept: 'text/html' } });
    if (root.status !== 200 || root.headers['content-type'] !== 'text/html' || root.body !== '<h1>smoke</h1><p>accept=text/html</p>') fail('http GET /: ' + JSON.stringify(root));
    checkDate(root.headers.date, 'http GET /');
    const echo = await httpRequest(HTTP_PORT, { method: 'POST', path: '/echo', headers: { 'content-type': 'text/plain' }, body: 'shout this' });
    if (echo.status !== 201 || echo.headers['x-smoke'] !== 'echoed' || echo.body !== 'SHOUT THIS') fail('http POST /echo: ' + JSON.stringify(echo));
    checkDate(echo.headers.date, 'http POST /echo');
    hyper.http = `GET / ${root.status} (${root.body.length}B), POST /echo ${echo.status} ${JSON.stringify(echo.body)}`;

    // openapi: a spec-routed GET.
    const OPENAPI_PORT = 8081;
    const openapiServer = await startServer({ protocol: 'openapi', port: OPENAPI_PORT, instruction: 'Serve the todo API.', startup_params: { spec: TODO_SPEC } });
    const todos = await httpRequest(OPENAPI_PORT, { path: '/todos', headers: { accept: 'application/json' } });
    if (todos.status !== 200 || !String(todos.headers['content-type']).startsWith('application/json')) fail('openapi GET /todos: ' + JSON.stringify(todos));
    const todoList = JSON.parse(todos.body);
    if (todoList[0]?.title !== 'Buy milk' || todoList[0]?.path !== '/todos') fail('openapi GET /todos body: ' + todos.body);
    if (!serverRequests.some((r) => r.protocol === 'openapi' && r.context.matched_route)) fail('the openapi request reached the model without its matched route: ' + JSON.stringify(serverRequests.filter((r) => r.protocol === 'openapi')));
    checkDate(todos.headers.date, 'openapi GET /todos');
    hyper.openapi = `GET /todos ${todos.status} ${todos.body}`;

    // jsonrpc: a call answered with a result, and one answered with an error.
    const JSONRPC_PORT = 8082;
    const jsonrpcServer = await startServer({ protocol: 'jsonrpc', port: JSONRPC_PORT, instruction: 'Implement add(a, b).' });
    const rpc = (payload) => httpRequest(JSONRPC_PORT, { method: 'POST', path: '/', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
    const sum = await rpc({ jsonrpc: '2.0', method: 'add', params: [2, 3], id: 7 });
    const sumBody = JSON.parse(sum.body);
    if (sum.status !== 200 || sumBody.jsonrpc !== '2.0' || sumBody.result !== 5 || sumBody.id !== 7) fail('jsonrpc add: ' + JSON.stringify(sum));
    checkDate(sum.headers.date, 'jsonrpc add');
    const missing = await rpc({ jsonrpc: '2.0', method: 'nope', id: 'x' });
    const missingBody = JSON.parse(missing.body);
    if (missingBody.error?.code !== -32601 || missingBody.id !== 'x') fail('jsonrpc error: ' + JSON.stringify(missing));
    hyper.jsonrpc = `add(2,3) -> ${sum.body}; nope -> error ${missingBody.error.code}`;

    // rss: the feed the model described, rendered to XML by the server.
    const RSS_PORT = 8083;
    await startServer({ protocol: 'rss', port: RSS_PORT, instruction: 'Serve a news feed.' });
    const feed = await httpRequest(RSS_PORT, { path: '/news.xml', headers: { accept: 'application/rss+xml' } });
    if (feed.status !== 200 || !/xml/.test(String(feed.headers['content-type']))) fail('rss GET /news.xml: ' + JSON.stringify(feed));
    for (const needle of ['<rss', '<title>Smoke News</title>', '<description>Served from /news.xml</description>', '<title>First post</title>']) {
        if (!feed.body.includes(needle)) fail('rss feed lacks ' + needle + ': ' + feed.body);
    }
    checkDate(feed.headers.date, 'rss GET /news.xml');
    hyper.rss = `GET /news.xml ${feed.status} (${feed.body.length}B of RSS)`;

    // http2: prior-knowledge h2c through node:http2 (nghttp2). NetGet's http2 server is the
    // `h2` crate rather than hyper, and it sets no Date header.
    const HTTP2_PORT = 8084;
    const http2Server = await startServer({ protocol: 'http2', port: HTTP2_PORT, instruction: 'Greet every request.' });
    const h2 = await http2Request(HTTP2_PORT, '/greet?who=smoke');
    if (h2.status !== 200 || h2.headers['x-smoke'] !== 'h2' || h2.body !== 'h2 says hi to /greet?who=smoke') fail('http2 GET /greet: ' + JSON.stringify(h2));
    hyper.http2 = `GET /greet?who=smoke ${h2.status} ${JSON.stringify(h2.body)}`;

    // The HTTP-family clients in the browser: each speaks through the shared transport
    // (src/client/http_fetch) over the virtual loopback to NetGet's own server of its protocol.
    const webClients = {};
    // An event parked for the human on a client, as the dashboard's "waiting for YOUR answer"
    // rows show it. A client the dashboard creates routes everything after its connect event
    // to `manual`, so that is where the response lands.
    async function parkedOn(clientId, eventType, matches = () => true) {
        let found = null;
        await waitFor(() => {
            netget.intercepts((json) => {
                const rows = JSON.parse(json);
                found = rows.find((r) => r.owner.kind === 'client' && r.owner.id === clientId && r.event_type === eventType && matches(r.event_data || {})) || found;
            });
            return found !== null;
        }, `a ${eventType} parked on client #${clientId}`, 20000);
        return found;
    }
    async function connectViaButton(serverId, protocol) {
        let made = null;
        netget.connect_client_to_server(serverId, (json) => { made = JSON.parse(json); });
        await waitFor(() => made !== null, `[ + ${protocol} client ] to answer`);
        if (made.error) fail(`[ + ${protocol} client ]: ` + made.error);
        let rows = null;
        netget.clients((json) => { rows = JSON.parse(json); });
        await waitFor(() => rows !== null, 'clients()');
        const row = rows.find((c) => c.id === made.id);
        if (!row || row.status !== 'Connected') fail(`the [ + ${protocol} client ] client is not connected: ` + JSON.stringify(rows));
        return made;
    }
    async function send(clientId, action) {
        let outcome = null;
        netget.send_to_client(clientId, JSON.stringify(action), (json) => { outcome = JSON.parse(json); });
        await waitFor(() => outcome !== null, `send_to_client(${action.type}) to answer`, 45000);
        const detail = outcome.Executed && outcome.Executed.detail;
        if (!detail) fail(`[ send ] ${action.type} was not executed: ` + JSON.stringify(outcome));
        return detail;
    }

    // jsonrpc: [ + JSON-RPC client ] on the jsonrpc server's card, then [ send ] add(2, 3). The
    // server's model computes 5; the client reads it and parks the response for the human.
    const rpcClient = await connectViaButton(jsonrpcServer.id, 'jsonrpc');
    if (rpcClient.remote_addr !== `127.0.0.1:${JSONRPC_PORT}`) fail('[ + jsonrpc client ] made the wrong client: ' + JSON.stringify(rpcClient));
    const rpcDetail = await send(rpcClient.id, { type: 'send_jsonrpc_request', method: 'add', params: [2, 3], id: 41 });
    if (!rpcDetail.includes('HTTP 200') || !rpcDetail.includes('JSON-RPC response received')) fail('jsonrpc [ send ]: ' + rpcDetail);
    const rpcParked = await parkedOn(rpcClient.id, 'jsonrpc_response_received');
    if (rpcParked.event_data?.result !== 5 || rpcParked.event_data?.id !== 41) fail('the jsonrpc response did not reach the client intact: ' + JSON.stringify(rpcParked));
    webClients.jsonrpc = `[ + client ] #${rpcClient.id}, [ send ] add(2,3) -> ${rpcDetail}; parked result ${rpcParked.event_data.result}`;

    // The transport has no TLS: an https:// endpoint is refused at connect, naming why.
    let rpcRefused = null;
    netget.start_client(JSON.stringify({ protocol: 'jsonrpc', remote_addr: `https://127.0.0.1:${JSONRPC_PORT}`, instruction: 'Call add.' }), (json) => { rpcRefused = JSON.parse(json); });
    await waitFor(() => rpcRefused !== null, 'start_client (jsonrpc, https) to answer');
    if (!rpcRefused.error || !rpcRefused.error.includes('https:// is not available')) fail('an https:// jsonrpc client was not refused with the reason: ' + JSON.stringify(rpcRefused));

    // elasticsearch: NetGet's Elasticsearch server, [ + client ], [ send ] a search.
    const ES_PORT = 8085;
    const esServer = await startServer({ protocol: 'elasticsearch', port: ES_PORT, instruction: 'Serve a small library index.' });
    const esClient = await connectViaButton(esServer.id, 'elasticsearch');
    const esDetail = await send(esClient.id, { type: 'search', index: 'books', query: { match: { title: 'dune' } } });
    if (!esDetail.includes('HTTP 200')) fail('elasticsearch [ send ]: ' + esDetail);
    const esAsked = serverRequests.filter((r) => r.protocol === 'elasticsearch');
    if (!esAsked.some((r) => r.context.index === 'books' && String(r.context.request_body).includes('dune'))) fail('the search did not reach the Elasticsearch server\'s model: ' + JSON.stringify(esAsked));
    const esParked = await parkedOn(esClient.id, 'elasticsearch_response_received');
    if (!JSON.stringify(esParked.event_data).includes('"title":"Dune"')) fail('the Elasticsearch hits did not reach the client: ' + JSON.stringify(esParked));
    webClients.elasticsearch = `[ + client ] #${esClient.id}, [ send ] search -> ${esDetail}; parked hit "Dune"`;

    // OpenAPI pairing inherits the running server's spec and targets its local base URL.
    const oaPair = await connectViaButton(openapiServer.id, 'openapi');
    await send(oaPair.id, { type: 'execute_operation', operation_id: 'listTodos', path_params: {}, query_params: {} });
    const oaPairReply = await parkedOn(oaPair.id, 'openapi_operation_response');
    if (oaPairReply.event_data.status_code !== 200 || !String(oaPairReply.event_data.body).includes('Buy milk')) fail('the inherited OpenAPI spec did not complete a request: ' + JSON.stringify(oaPairReply));

    // A separately model-driven client still chooses operations on connect and response.
    let oaClient = null;
    netget.start_client(JSON.stringify({ protocol: 'openapi', remote_addr: `127.0.0.1:${OPENAPI_PORT}`, instruction: 'List the todos.', startup_params: { spec: TODO_SPEC } }), (json) => { oaClient = JSON.parse(json); });
    await waitFor(() => oaClient !== null, 'start_client (openapi) to answer');
    if (oaClient.error) fail('start_client openapi: ' + oaClient.error);
    await waitFor(() => clientResponses.openapi.length > 0, 'the openapi client\'s response reported to the model', 20000);
    const oaFirst = clientResponses.openapi[0];
    if (oaFirst.status_code !== 200 || JSON.parse(oaFirst.body)[0]?.title !== 'Buy milk') fail('the openapi response did not reach the client: ' + JSON.stringify(oaFirst));
    if (!serverRequests.some((r) => r.protocol === 'openapi' && JSON.stringify(r.context).includes('smoke'))) fail('the model\'s query parameter did not reach the openapi server: ' + JSON.stringify(serverRequests.filter((r) => r.protocol === 'openapi')));
    const oaDetail = await send(oaClient.id, { type: 'execute_operation', operation_id: 'listTodos', path_params: {}, query_params: {} });
    await waitFor(() => clientResponses.openapi.length > 1, 'the injected operation\'s response reported to the model', 20000);
    webClients.openapi = `ClientForm #${oaClient.id}: model ran listTodos -> ${oaFirst.status_code} ${oaFirst.body}; [ send ] -> ${oaDetail}`;

    // bitcoin: Bitcoin Core RPC is JSON-RPC over HTTP, and NetGet's `bitcoin` server is the P2P
    // protocol, so the peer is NetGet's http server answering as bitcoind would. The RPC
    // credentials go out as Basic auth, which the server's request must show.
    let btcClient = null;
    netget.start_client(JSON.stringify({ protocol: 'bitcoin', remote_addr: `127.0.0.1:${HTTP_PORT}`, instruction: 'Watch the chain.', startup_params: { rpc_user: 'smoke', rpc_password: 'pw' } }), (json) => { btcClient = JSON.parse(json); });
    await waitFor(() => btcClient !== null, 'start_client (bitcoin) to answer');
    if (btcClient.error) fail('start_client bitcoin: ' + btcClient.error);
    const btcDetail = await send(btcClient.id, { type: 'get_blockchain_info' });
    if (!btcDetail.includes("'getblockchaininfo' -> HTTP 200 (result)")) fail('bitcoin [ send ]: ' + btcDetail);
    await waitFor(() => clientResponses.bitcoin.length > 0, 'the bitcoin RPC response reported to the model', 20000);
    const btc = clientResponses.bitcoin[0];
    if (btc.result?.blocks !== 101 || btc.result?.called !== 'getblockchaininfo') fail('the RPC result did not reach the client: ' + JSON.stringify(btc));
    const rpcSeen = serverRequests.find((r) => r.protocol === 'http' && String(r.context.body).includes('getblockchaininfo'));
    const auth = rpcSeen && headerOf(rpcSeen.context.headers, 'authorization');
    if (auth !== 'Basic ' + Buffer.from('smoke:pw').toString('base64')) fail('the RPC credentials did not arrive as Basic auth: ' + JSON.stringify(rpcSeen && rpcSeen.context.headers));
    webClients.bitcoin = `ClientForm #${btcClient.id} -> http :${HTTP_PORT}: [ send ] ${btcDetail}; blocks ${btc.result.blocks}; Basic auth arrived`;

    // npm, pypi, maven: each registry client through [ + client ] on NetGet's own server of its
    // protocol (the pairing form explicitly chooses http://), [ send ] a lookup, and the answer the
    // server's model wrote found parked on the client.
    const registries = [
        { protocol: 'npm', port: 8086, action: { type: 'get_package_info', package_name: 'smoke-pkg' }, event: 'npm_package_info_received', marker: 'served to the smoke test' },
        { protocol: 'pypi', port: 8087, action: { type: 'get_package_info', package_name: 'smoke-pkg' }, event: 'pypi_package_info_received', marker: 'served to the smoke test from' },
        { protocol: 'maven', port: 8088, action: { type: 'download_pom', group_id: 'net.netget', artifact_id: 'smoke', version: '1.0.0' }, event: 'maven_pom_received', marker: '<artifactId>smoke</artifactId>' },
    ];
    for (const r of registries) {
        const server = await startServer({ protocol: r.protocol, port: r.port, instruction: `Serve a tiny ${r.protocol} registry.` });
        const client = await connectViaButton(server.id, r.protocol);
        if (client.remote_addr !== `http://127.0.0.1:${r.port}`) fail(`the ${r.protocol} pair must explicitly use HTTP: ` + JSON.stringify(client));
        const detail = await send(client.id, r.action);
        if (!serverRequests.some((q) => q.protocol === r.protocol)) fail(`the ${r.protocol} request never reached the server's model; [ send ] said ` + detail);
        const parked = await parkedOn(client.id, r.event);
        if (!JSON.stringify(parked.event_data).includes(r.marker)) fail(`the ${r.protocol} answer did not reach the client: ` + JSON.stringify(parked));
        webClients[r.protocol] = `[ + client ] #${client.id} -> http://127.0.0.1:${r.port}, [ send ] ${r.action.type} -> ${detail}; parked ${r.event}`;
    }
    // A registry named https:// is refused in the browser, with the reason.
    let npmRefused = null;
    netget.start_client(JSON.stringify({ protocol: 'npm', remote_addr: 'https://registry.npmjs.org', instruction: 'Look up left-pad.' }), (json) => { npmRefused = JSON.parse(json); });
    await waitFor(() => npmRefused !== null, 'start_client (npm, https) to answer');
    if (!npmRefused.error || !npmRefused.error.includes('https:// is not available')) fail('an https:// npm registry was not refused with the reason: ' + JSON.stringify(npmRefused));

    // torrent-tracker: [ + client ] (a bare address becomes http://host:port/announce),
    // [ send ] an announce, and the tracker's bencoded reply — a binary compact peer list —
    // decoded on the client: 127.0.0.1:6881 is the six bytes 127 0 0 1 26 225.
    const TRACKER_PORT = 8089;
    const trackerServer = await startServer({ protocol: 'torrent-tracker', port: TRACKER_PORT, instruction: 'Track one swarm.' });
    const trackerClient = await connectViaButton(trackerServer.id, 'torrent-tracker');
    const infoHash = '0123456789abcdef0123456789abcdef01234567';
    const announceDetail = await send(trackerClient.id, { type: 'tracker_announce', info_hash: infoHash, peer_id: '2d4e47303030312d736d6f6b6530303030303030', port: 6881, uploaded: 0, downloaded: 0, left: 0, event: 'started' });
    const announced = serverRequests.find((q) => q.protocol === 'torrent-tracker');
    if (!announced || !JSON.stringify(announced.context).toLowerCase().includes(infoHash)) fail('the announce did not reach the tracker\'s model with its info_hash: ' + JSON.stringify(announced) + '; [ send ] said ' + announceDetail);
    const peers = await parkedOn(trackerClient.id, 'tracker_announce_response', (d) => d.interval !== undefined);
    if (peers.event_data.interval !== 900 || peers.event_data.complete !== 3 || !String(peers.event_data.peers).includes('127, 0, 0, 1, 26, 225')) fail('the compact peer list did not reach the client intact: ' + JSON.stringify(peers));
    webClients['torrent-tracker'] = `[ + client ] #${trackerClient.id}, [ send ] announce -> ${announceDetail}; parked interval ${peers.event_data.interval}, peers ${peers.event_data.peers}`;

    // http2: [ + HTTP/2 client ] on the http2 server's card; the client speaks h2c with prior
    // knowledge through hyper's HTTP/2 client over the virtual loopback, its connection tasks
    // on the shim's spawn. [ send ] a GET; the server's model answers; the response, read as
    // HTTP/2, is parked on the client.
    const h2Client = await connectViaButton(http2Server.id, 'http2');
    const h2Detail = await send(h2Client.id, { type: 'send_http2_request', method: 'GET', path: '/from-netget?via=h2c' });
    const h2Parked = await parkedOn(h2Client.id, 'http2_response_received');
    const h2Data = h2Parked.event_data;
    if (h2Data.status_code !== 200 || h2Data.body !== 'h2 says hi to /from-netget?via=h2c' || h2Data.http_version !== 'HTTP/2.0' || headerOf(h2Data.headers, 'x-smoke') !== 'h2') fail('the HTTP/2 response did not reach the client as HTTP/2: ' + JSON.stringify(h2Parked) + '; [ send ] said ' + h2Detail);
    webClients.http2 = `[ + client ] #${h2Client.id}, [ send ] GET -> ${h2Detail}; parked ${h2Data.http_version} ${h2Data.status_code} ${JSON.stringify(h2Data.body)}`;

    // ollama: [ + Ollama client ] on NetGet's own Ollama server, [ send ] a generate request;
    // the server's model writes the completion, and it is parked on the client.
    const OLLAMA_PORT = 8092;
    const ollamaServer = await startServer({ protocol: 'ollama', port: OLLAMA_PORT, instruction: 'Answer as a tiny model.' });
    const ollamaClient = await connectViaButton(ollamaServer.id, 'ollama');
    const ollamaDetail = await send(ollamaClient.id, { type: 'send_generate_request', prompt: 'What is the capital of Smokeland?', model: 'smoke-model' });
    const generated = serverRequests.find((r) => r.protocol === 'ollama');
    if (!generated || !String(generated.context.prompt).includes('Smokeland')) fail('the generate request did not reach the Ollama server\'s model: ' + JSON.stringify(generated) + '; [ send ] said ' + ollamaDetail);
    const ollamaParked = await parkedOn(ollamaClient.id, 'ollama_response_received');
    if (!JSON.stringify(ollamaParked.event_data).includes('Smoke City, said smoke-model')) fail('the completion did not reach the Ollama client: ' + JSON.stringify(ollamaParked));
    webClients.ollama = `[ + client ] #${ollamaClient.id}, [ send ] generate -> ${ollamaDetail}; parked "Smoke City, said smoke-model"`;

    // oauth2 and openidconnect: the crates' own HTTP hook (`request_async`, `discover_async`)
    // is handed the transport in the browser. First exercise model-driven ClientForm clients:
    // the model asks for a client-credentials token, NetGet's server's model issues one, and
    // the token event (with the expiry the server chose) comes back to the model.
    const OAUTH2_PORT = 8090;
    const oauthServer = await startServer({ protocol: 'oauth2', port: OAUTH2_PORT, instruction: 'Issue tokens to smoke-app.' });
    let oauthRefused = null;
    netget.start_client(JSON.stringify({ protocol: 'oauth2', remote_addr: `127.0.0.1:${OAUTH2_PORT}`, instruction: 'Get a token.', startup_params: { client_id: 'smoke-app', token_url: 'https://127.0.0.1:1/token' } }), (json) => { oauthRefused = JSON.parse(json); });
    await waitFor(() => oauthRefused !== null, 'start_client (oauth2, https) to answer');
    if (!oauthRefused.error || !oauthRefused.error.includes('https:// is not available')) fail('an https:// token endpoint was not refused with the reason: ' + JSON.stringify(oauthRefused));
    let oauthClient = null;
    netget.start_client(JSON.stringify({ protocol: 'oauth2', remote_addr: `127.0.0.1:${OAUTH2_PORT}`, instruction: 'Get a client-credentials token.',
        startup_params: { client_id: 'smoke-app', client_secret: 'smoke-secret', token_url: `http://127.0.0.1:${OAUTH2_PORT}/token` } }), (json) => { oauthClient = JSON.parse(json); });
    await waitFor(() => oauthClient !== null, 'start_client (oauth2) to answer');
    if (oauthClient.error) fail('start_client oauth2: ' + oauthClient.error);
    await waitFor(() => clientResponses.oauth2.length > 0, 'the oauth2 token reported to the model', 20000);
    const oauthToken = clientResponses.oauth2[0];
    if (oauthToken.expires_in !== 1234 || oauthToken.scope === undefined) fail('the OAuth2 token did not reach the client: ' + JSON.stringify(oauthToken));
    const tokenAsked = serverRequests.find((r) => r.protocol === 'oauth2');
    if (!tokenAsked || tokenAsked.context.grant_type !== 'client_credentials') fail('the token request did not reach the OAuth2 server\'s model as client_credentials: ' + JSON.stringify(tokenAsked));
    const oauthDetail = await send(oauthClient.id, { type: 'exchange_client_credentials', scopes: 'read' });
    await waitFor(() => clientResponses.oauth2.length > 1, 'the injected token request reported to the model', 20000);
    webClients.oauth2 = `ClientForm #${oauthClient.id}: model asked for client_credentials -> token, expires_in ${oauthToken.expires_in}; [ send ] -> ${oauthDetail}; https token URL refused`;

    const oidcServer = await startServer({ protocol: 'openid', port: OIDC_PORT, instruction: 'Be an OpenID provider for smoke-app.' });
    let oidcClient = null;
    netget.start_client(JSON.stringify({ protocol: 'openidconnect', remote_addr: `http://127.0.0.1:${OIDC_PORT}`, instruction: 'Discover the provider and get a token.',
        startup_params: { client_id: 'smoke-app', client_secret: 'smoke-secret' } }), (json) => { oidcClient = JSON.parse(json); });
    await waitFor(() => oidcClient !== null, 'start_client (openidconnect) to answer');
    if (oidcClient.error) fail('start_client openidconnect: ' + oidcClient.error);
    await waitFor(() => clientResponses.oidc.some((c) => c.access_token !== undefined), 'the OIDC token reported to the model', 30000);
    const discovered = clientResponses.oidc.find((c) => c.issuer !== undefined);
    if (!discovered || discovered.issuer !== `http://127.0.0.1:${OIDC_PORT}` || discovered.token_endpoint !== `http://127.0.0.1:${OIDC_PORT}/token`) fail('discovery did not reach the client: ' + JSON.stringify(clientResponses.oidc));
    const oidcToken = clientResponses.oidc.find((c) => c.access_token !== undefined);
    if (oidcToken.expires_in !== 4321) fail('the OIDC token did not reach the client: ' + JSON.stringify(oidcToken));
    const oidcAsked = serverRequests.filter((r) => r.protocol === 'openid').map((r) => r.context.endpoint_type);
    for (const endpoint of ['discovery', 'jwks', 'token']) if (!oidcAsked.includes(endpoint)) fail(`the OpenID provider's model never saw a ${endpoint} request: ` + JSON.stringify(oidcAsked));
    webClients.openidconnect = `ClientForm #${oidcClient.id}: discovered ${discovered.issuer} (${oidcAsked.join(', ')}), token expires_in ${oidcToken.expires_in}`;

    // The page's pair button opens the real dashboard form for unknown credentials.
    // Type into its focused client_id field, fill the optional secret, then use the
    // form's keyboard Apply button. This exercises the UI, not a test-only parameter API.
    async function credentialPair(serverId, protocol) {
        const before = new Set();
        let listed = false;
        netget.clients((json) => { JSON.parse(json).forEach((c) => before.add(c.id)); listed = true; });
        await waitFor(() => listed, 'clients before credential form');
        const screenStart = screen.length;
        let opened = null;
        netget.connect_client_to_server(serverId, (json) => { opened = JSON.parse(json); });
        await waitFor(() => opened !== null, 'the credential form to open');
        if (opened.error || opened.configuration_required !== 'client_id' || opened.form_opened !== true) fail('pairing did not request client_id in a dashboard form: ' + JSON.stringify(opened));
        await waitFor(() => screen.slice(screenStart).includes(`New ${opened.protocol} client`), 'the credential form to paint');
        netget.text('smoke-app\n');
        netget.key(JSON.stringify({ key: 'Tab' }));
        netget.text('smoke-secret\n');
        // From client_secret: back through client_id, remote_addr, Cancel, Wireshark, Apply.
        for (let i = 0; i < 5; i++) netget.key(JSON.stringify({ key: 'Tab', shift: true }));
        netget.key(JSON.stringify({ key: 'Enter' }));
        let created = null;
        await waitFor(() => {
            netget.clients((json) => { created = JSON.parse(json).find((c) => !before.has(c.id) && c.protocol.toLowerCase() === protocol && c.status === 'Connected') || created; });
            return created !== null;
        }, `the configured ${protocol} client to connect`, 20000);
        // Creation must finish and dismiss its modal, including OIDC's initial discovery.
        await waitFor(() => screen.slice(screenStart).includes(`Connected client #${created.id}`), 'the credential form apply to finish', 20000);
        return created;
    }
    const oauthPair = await credentialPair(oauthServer.id, 'oauth2');
    await send(oauthPair.id, { type: 'exchange_client_credentials', scopes: 'read' });
    const oauthPairToken = await parkedOn(oauthPair.id, 'oauth2_token_obtained');
    if (oauthPairToken.event_data.expires_in !== 1234) fail('the configured OAuth2 pair failed to receive its token: ' + JSON.stringify(oauthPairToken));
    webClients.oauth2 += '; paired through credential form, local token endpoint received token';

    const oidcPair = await credentialPair(oidcServer.id, 'openidconnect');
    if (oidcPair.remote_addr !== `http://127.0.0.1:${OIDC_PORT}`) fail('the OIDC pair must use an absolute local URL: ' + JSON.stringify(oidcPair));
    await send(oidcPair.id, { type: 'exchange_client_credentials', scopes: 'openid' });
    const oidcPairToken = await parkedOn(oidcPair.id, 'oidc_token_received');
    if (oidcPairToken.event_data.expires_in !== 4321) fail('the configured OIDC pair failed to receive its token: ' + JSON.stringify(oidcPairToken));
    webClients.openidconnect += '; paired through credential form, discovery completed and token received';

    Object.assign(hyper, await checkRemainingHttpServers({ startServer, httpRequest, checkDate, fail }));

    if (panics.length) fail('the wasm instance panicked:\n' + panics.join('\n'));

    console.log('ok: dashboard painted, tcp, udp, http, openapi, jsonrpc, rss and http2 servers started, virtual connections round-tripped through the model bridge');
    console.log('    thinking: a reply\'s reasoning reached the dashboard; thinking.js split <think> streams and left other models\' text whole');
    console.log('    composer: ' + composed[0].actions.length + ' actions offered, default ' + composed[0].entry.name + ', example bytes ' + JSON.stringify(composerReceived.join('')) + ' reached the peer');
    console.log('    http client: [ + http client ] connected client #' + viaButton.id + ' to :' + HTTP_PORT + '; client #' + httpClient.id + ' read ' + first.status_code + ' ' + JSON.stringify(first.body) + ' and, via [ send ], ' + detail.split('-> ')[1] + '; https refused');
    for (const [name, line] of Object.entries(hyper)) console.log(`    ${name} (node client): ${line}`);
    for (const [name, line] of Object.entries(webClients)) console.log(`    ${name} client: ${line}`);
    console.log('    Date headers checked:', dates.length, '| latest:', dates[dates.length - 1]);
    console.log('    requests:', requests.length, '| tcp received:', JSON.stringify(received.join('')), '| udp received:', JSON.stringify(datagrams), '| closed:', closed);
    process.exit(0);
} catch (e) {
    fail(e.message || String(e));
}
