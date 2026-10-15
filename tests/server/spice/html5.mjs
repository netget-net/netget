// spice-html5 in headless Chrome against a NetGet SPICE server. websockify serves spice-html5's
// files and carries its WebSocket to the SPICE port, on the same port.
//   node html5.mjs WEB_PORT PASSWORD PANEL_X PANEL_Y CORNER_X CORNER_Y   (Chrome from $NETGET_CHROME)
// Prints one JSON line: {"ok": true, "size": [w, h], "panel": [r, g, b], "corner": [r, g, b],
// "after": [r, g, b]} — the panel before and after the key `x` is typed into the page — or
// {"ok": false, "error": ...}. Node 22+ (global WebSocket and fetch).
import {spawn} from 'node:child_process';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const [web, password, px, py, cx, cy] = process.argv.slice(2);
const chromePath = process.env.NETGET_CHROME;
if (!chromePath) throw new Error('NETGET_CHROME must name a Chrome or Chromium binary');
const profile = await mkdtemp(join(tmpdir(), 'netget-spice-html5-chrome-'));
const chrome = spawn(chromePath, ['--headless', '--no-sandbox', '--disable-gpu', '--disable-background-networking',
  '--remote-debugging-port=0', '--no-first-run', '--no-default-browser-check', `--user-data-dir=${profile}`,
  '--window-size=1024,768', 'about:blank'], {stdio: ['ignore', 'ignore', 'pipe']});
let diagnostic = '';
chrome.stderr.on('data', chunk => {diagnostic = (diagnostic + chunk).slice(-8192)});
let socket;
const result = {ok: false};
const sleep = ms => new Promise(r => setTimeout(r, ms));
try {
  let active;
  for (let i = 0; i < 600 && !active; i++) {
    try {active = (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')} catch {await sleep(100)}
  }
  if (!active) throw new Error(`Chrome did not start: ${diagnostic}`);
  const targets = await (await fetch(`http://127.0.0.1:${active[0]}/json/list`)).json();
  socket = new WebSocket(targets.find(t => t.type === 'page').webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {socket.onopen = resolve; socket.onerror = reject});
  const pending = new Map(); let id = 0; const consoleLines = [];
  socket.onmessage = event => {
    const x = JSON.parse(event.data);
    if (x.id) {const p = pending.get(x.id); pending.delete(x.id); x.error ? p.reject(new Error(JSON.stringify(x.error))) : p.resolve(x.result)}
    else if (x.method === 'Runtime.consoleAPICalled') consoleLines.push(x.params.args.map(a => a.value).join(' '));
  };
  const rpc = (method, params = {}) => new Promise((resolve, reject) => {const key = ++id; pending.set(key, {resolve, reject}); socket.send(JSON.stringify({id: key, method, params}))});
  const evaluate = async expression => (await rpc('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true})).result.value;
  await rpc('Runtime.enable');
  await rpc('Page.enable');
  const url = `http://127.0.0.1:${web}/spice_auto.html?host=127.0.0.1&port=${web}&password=${encodeURIComponent(password)}`;
  await rpc('Page.navigate', {url});
  const pixel = (x, y) => `(() => {const c = document.getElementById('spice_surface_0'); if (!c) return null;
    const d = c.getContext('2d').getImageData(${x}, ${y}, 1, 1).data; return [d[0], d[1], d[2], d[3]]})()`;
  // Wait for the primary surface and for something to be drawn on it.
  let panel;
  for (let i = 0; i < 600; i++) {
    panel = await evaluate(pixel(px, py));
    if (panel && panel[3] === 255 && (panel[0] || panel[1] || panel[2])) break;
    await sleep(100);
  }
  if (!panel) throw new Error(`spice-html5 never created its surface; console: ${consoleLines.slice(-20).join(' | ')}`);
  result.size = await evaluate(`(() => {const c = document.getElementById('spice_surface_0'); return [c.width, c.height]})()`);
  result.panel = panel.slice(0, 3);
  result.corner = (await evaluate(pixel(cx, cy))).slice(0, 3);
  // Type `x` into the focused surface: spice-html5 turns the key event into a scancode. A
  // headless page is never the focused window unless focus is emulated, and key events go
  // nowhere without it.
  await rpc('Emulation.setFocusEmulationEnabled', {enabled: true});
  await evaluate(`document.getElementById('spice_surface_0').focus()`);
  result.focused = await evaluate(`document.activeElement && document.activeElement.id`);
  // The inputs channel links after the display: a key typed before it is ready is dropped.
  for (let i = 0; i < 300; i++) {
    result.inputs = await evaluate(`(() => {const c = document.getElementById('spice_surface_0'); return c.sc && c.sc.inputs ? c.sc.inputs.state : 'none'})()`);
    if (result.inputs === 'ready') break;
    await sleep(100);
  }
  if (result.inputs !== 'ready') throw new Error(`spice-html5's inputs channel is ${result.inputs}`);
  for (const type of ['keyDown', 'keyUp']) {
    await rpc('Input.dispatchKeyEvent', {type, key: 'x', code: 'KeyX', windowsVirtualKeyCode: 88, nativeVirtualKeyCode: 88, text: type === 'keyDown' ? 'x' : undefined});
  }
  let after = panel;
  for (let i = 0; i < 200; i++) {
    after = await evaluate(pixel(px, py));
    if (after && (after[0] !== panel[0] || after[1] !== panel[1] || after[2] !== panel[2])) break;
    await sleep(100);
  }
  result.after = after.slice(0, 3);
  result.console = consoleLines.slice(-10);
  result.ok = true;
} catch (e) {
  result.error = String(e && e.stack || e);
} finally {
  try {socket && socket.close()} catch {}
  chrome.kill('SIGKILL');
  await rm(profile, {recursive: true, force: true}).catch(() => {});
}
console.log(JSON.stringify(result));
process.exit(0);
