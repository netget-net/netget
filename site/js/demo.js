// NetGet in the browser: the standalone interactive demo.
//
// Three machines run here, and none of them is a mock of NetGet:
//
//   1. NetGet itself, compiled to WebAssembly (crates/netget-web). Its dashboard renders
//      into an xterm.js terminal; its servers listen on a virtual network that lives inside
//      the wasm instance. About a second after it boots, this page opens a Telnet server in
//      it through the same `start_server` call the dashboard's own form uses.
//   2. A Telnet client on the same page, which connects to that server a second later
//      through NetGet.connect(port) — a real TcpStream::connect on the virtual network. It
//      edits a line locally and echoes what you type, as telnet(1) does in line mode.
//   3. The model. NetGet hands every LLM request to this page as JSON (the full prompt and
//      every action it offers). The visitor picks the model in one select: the browser's
//      built-in model (the Prompt API: Gemini Nano in Chrome, Phi-4-mini in Edge) where it
//      has one, and the WebLLM models on the GPU, or "You are the model": the visitor
//      answers through ./composer.js. While the chosen model loads, requests wait for it
//      (for two minutes at most, then the visitor has them); while it needs a click to
//      download, the visitor answers. While a model answers, the LLM panel shows what it
//      writes as it writes it: a model that reasons natively (Qwen3) shows its thinking in a
//      "Thinking…" block (./thinking.js splits it out) and then its answer; every other
//      model shows only its answer.
//
// The wasm bundle is built by ./web/build.sh into site/demo/pkg/.

import { mountComposer, offeredActions, entriesFromEnvelope, buildReply } from './composer.js';
import { splitThinking } from './thinking.js';
import { TelnetDecoder } from './telnet.js';

const PKG = '../demo/pkg/netget_web.js';
const WEBLLM_URL = 'https://esm.run/@mlc-ai/web-llm@0.2.85';

// WebLLM's prebuilt model ids, the name the page shows, and roughly what the download is
// (the weights' total in each model's ndarray-cache.json on Hugging Face; WebLLM 0.2.85's
// prebuilt config gives only the VRAM, which is larger: 2.0 GB for Qwen3 1.7B, 3.4 GB for
// Qwen3 4B). `thinks`: the model reasons in a `<think>` block before it answers.
const WEBLLM_MODELS = [
    { id: 'Qwen2.5-1.5B-Instruct-q4f16_1-MLC', name: 'Qwen2.5 1.5B', size: '~1 GB' },
    { id: 'Qwen3-1.7B-q4f16_1-MLC', name: 'Qwen3 1.7B', size: '~1 GB', thinks: true },
    { id: 'Llama-3.2-3B-Instruct-q4f16_1-MLC', name: 'Llama 3.2 3B', size: '~2 GB' },
    { id: 'Qwen2.5-3B-Instruct-q4f16_1-MLC', name: 'Qwen2.5 3B', size: '~2 GB' },
    { id: 'Qwen3-4B-q4f16_1-MLC', name: 'Qwen3 4B', size: '~2.3 GB', thinks: true },
    { id: 'Hermes-3-Llama-3.1-8B-q4f16_1-MLC', name: 'Hermes 3 8B', size: '~5 GB' },
];

// The dashboard's widths (see makeTerm): its two columns sit side by side from 80 columns
// (src/tui/render/mod.rs's TWO_COLUMN_WIDTH) and stack below that, down to 40 (MIN_WIDTH).
const DASH_COLS = { wide: 80, narrow: 48 };

// Where the model select is too narrow for the full option labels (about 30 characters).
const NARROW = window.matchMedia('(max-width: 600px)');

// The context window every WebLLM model is loaded with. WebLLM's prebuilt configs give these
// models 4096 tokens, and a NetGet request for a Telnet event is about 3900 of them before the
// model writes anything: measured on the page with the real Qwen3 1.7B, the connect event left
// it 169 tokens, it ran out inside its <think> block (finish_reason "length") and answered
// nothing, and the next line's prompt (4146 tokens) was refused outright. 8192 holds the
// prompt plus what a model may write; every model listed supports at least 32K.
const WEBLLM_CONTEXT = 8192;

// What a thinking model may write for one request, thinking included; one that uses it all
// without closing its `<think>` block is asked again with thinking off (answerWithWebLlm).
const THINKING_MAX_TOKENS = 1024;

const TELNET_PORT = 2323;
const SERVER_AFTER_MS = 1000;   // after NetGet boots, open the Telnet server
const CLIENT_AFTER_MS = 2000;   // after NetGet boots, connect the Telnet client

// Short, and answerable in one line by a small model or by a person filling in a form.
//
// Every model request carries the instruction, the server's memory and one event, with no
// record of what was said before it, and whatever a small model is asked to do it reads best
// at the end. So each event that needs its own words gets them in its own rule: a `llm` event
// handler adds its instruction to that event's prompt alone, after the event's data, as the
// last thing the model reads (web/README.md has the measurements).
//
// Connection-open is handled statically; only typed lines reach the model, and the rule for
// them asks for the one-line answer a small model or a person can give.
const TELNET_INSTRUCTION = 'Provide life coaching services over Telnet.';
const TELNET_LINE_RULE = 'Answer with send_telnet_line: one or two short lines of plain text, '
    + 'under 200 characters.';
const TELNET_EVENT_HANDLERS = [{
    event_pattern: 'telnet_connection_opened',
    handler: { type: 'static', actions: [] },
}, {
    event_pattern: 'telnet_message_received',
    handler: { type: 'llm', instruction: TELNET_LINE_RULE },
}];

// Options for the Prompt API: English text in, English text out.
const LM_OPTIONS = {
    expectedInputs: [{ type: 'text', languages: ['en'] }],
    expectedOutputs: [{ type: 'text', languages: ['en'] }],
};

const $ = (sel, root = document) => root.querySelector(sel);
const enc = new TextEncoder();

const app = {
    netget: null,
    dash: null,           // xterm for the dashboard
    telnet: { term: null, conn: null, line: '', serverUp: false, serverId: null, typing: false },
    models: [],           // what the select lists, each with its own state
    selected: null,       // the id the select shows
    active: null,         // the model answering, or null: the visitor answers
    webllm: { module: null, importing: null, checking: null },
    queue: [],            // model requests not yet being answered
    current: null,        // the one being answered
};

function pageTheme() {
    const t = document.documentElement.getAttribute('data-theme');
    if (t) return t;
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function xtermTheme() {
    const dark = pageTheme() !== 'light';
    return dark
        ? { background: '#0a0c11', foreground: '#dbe2ee', cursor: '#38bdf8', selectionBackground: '#233a55' }
        : { background: '#ffffff', foreground: '#1a2231', cursor: '#0369a1', selectionBackground: '#cfe3f5' };
}

// A terminal that fills its host element and refits whenever the host changes size. With
// `cols`, the font follows the width: 13px wherever `cols.wide` columns fit at 13px (the
// dashboard's two columns side by side), otherwise the largest size, from 13px down to 6px,
// that fits `cols.narrow` (the dashboard stacks its columns below 80, and a phone gets about
// 48 columns of 11px text instead of 80 columns of 6px text).
function makeTerm(el, opts = {}, onFit = () => {}, { cols = null } = {}) {
    const term = new window.Terminal(Object.assign({
        cursorBlink: false,
        fontFamily: "'JetBrains Mono', ui-monospace, monospace",
        fontSize: 13,
        lineHeight: 1.15,
        theme: xtermTheme(),
        scrollback: 0,
        allowProposedApi: true,
    }, opts));
    const fit = new window.FitAddon.FitAddon();
    term.loadAddon(fit);
    term.open(el);
    let last = '';
    const refit = () => {
        try { fit.fit(); } catch (e) { return; }
        if (cols && term.cols) {
            const now = term.options.fontSize;
            const at13 = now * term.cols / 13;
            const want = at13 >= cols.wide
                ? 13
                : Math.max(6, Math.min(13, Math.floor((now * term.cols / cols.narrow) * 2) / 2));
            if (want !== now) {
                term.options.fontSize = want;
                requestAnimationFrame(refit);
                return;
            }
        }
        const size = term.cols + 'x' + term.rows;
        if (size !== last) { last = size; onFit(term.cols, term.rows); }
    };
    refit();
    new ResizeObserver(refit).observe(el);
    // A webfont arriving changes the cell size without changing the element's size, and
    // xterm.js picks the new cell up on a later render. So after every render, if the rows no
    // longer fill the element exactly, fit again (a fit that changes nothing renders nothing).
    let queued = false;
    term.onRender?.(() => {
        if (queued) return;
        const screen = el.querySelector('.xterm-screen');
        if (!screen || !term.rows) return;
        const row = screen.offsetHeight / term.rows;
        const spare = el.clientHeight - screen.offsetHeight;
        if (spare < 0 || spare >= row) {
            queued = true;
            requestAnimationFrame(() => { queued = false; refit(); });
        }
    });
    return term;
}

function escapeHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ---------------------------------------------------------------------------------------
// Dashboard terminal: keys from the DOM, mouse from xterm's SGR reports, bytes back in.
// ---------------------------------------------------------------------------------------

function wireDashboardInput(term, netget) {
    term.attachCustomKeyEventHandler((ev) => {
        if (ev.type !== 'keydown') return false;
        // Paste arrives through onData; browser shortcuts stay with the browser.
        if ((ev.ctrlKey || ev.metaKey) && (ev.key === 'v' || ev.key === 'V')) return false;
        if (ev.metaKey && !ev.ctrlKey) return false;
        const took = netget.key(JSON.stringify({
            key: ev.key, ctrl: ev.ctrlKey, alt: ev.altKey, shift: ev.shiftKey, meta: ev.metaKey,
        }));
        if (took) ev.preventDefault();
        return false;
    });

    const sgr = /\x1b\[<(\d+);(\d+);(\d+)([Mm])/g;
    term.onData((data) => {
        let plain = '';
        let last = 0;
        let m;
        while ((m = sgr.exec(data))) {
            plain += data.slice(last, m.index);
            last = sgr.lastIndex;
            const b = +m[1];
            const low = b & 3;
            let kind;
            if (b & 64) kind = low === 0 ? 'scrollup' : 'scrolldown';
            else if (b & 32) kind = low === 3 ? 'moved' : 'drag';
            else kind = m[4] === 'M' ? 'down' : 'up';
            netget.mouse(JSON.stringify({
                kind,
                button: ['left', 'middle', 'right'][low] || 'left',
                col: +m[2] - 1, row: +m[3] - 1,
                shift: !!(b & 4), alt: !!(b & 8), ctrl: !!(b & 16),
            }));
        }
        sgr.lastIndex = 0;
        plain += data.slice(last);
        if (plain) netget.text(plain);
    });
}

// ---------------------------------------------------------------------------------------
// Who answers. The select names it: a model, or "You are the model". A request goes to the
// model answering now if there is one; otherwise, while the selected model is on its way
// (being looked for, started, loaded from the cache, or downloading once the visitor asked),
// it waits for that model; otherwise the visitor answers it.
// ---------------------------------------------------------------------------------------

// How long a request waits for a model that is still loading before the visitor gets it.
//
// NetGet waits for the page's answer to a request for LLM_TIMEOUT (900 s, in
// crates/netget-web/src/lib.rs) and then fails it closed. NetGet hands the page one request
// at a time (its rate limiter has a single permit), so a
// second network request waits behind this one for at most 300 s (the limiter's queue
// timeout) before it fails. Two minutes is well inside both, and leaves the visitor the rest.
// A model that becomes ready later still takes the request over if the visitor has not
// started on it.
const MODEL_WAIT_MS = 120_000;

// { to: 'model', model } | { to: 'wait', model } | { to: 'you' }
function route() {
    if (app.selected === YOU) return { to: 'you' };
    if (app.active) return { to: 'model', model: app.active };
    const m = selectedModel();
    if (m && (m.state === 'loading' || m.state === 'checking' || m.state === 'loadable')) return { to: 'wait', model: m };
    return { to: 'you' };
}

function answererName() {
    const r = route();
    return r.to === 'you' ? 'you' : r.model.name;
}

// Tell every place that names the answerer: the LLM machine (`data-answerer`), and NetGet
// itself (the dashboard's status bar and the `model` of every request).
function renderWho() {
    const name = answererName();
    const machine = $('.machine-model');
    if (machine) machine.dataset.answerer = name;
    if (app.netget && app.told !== name) {
        app.told = name;
        app.netget.set_models(JSON.stringify([name]));
        if (typeof app.netget.set_model === 'function') app.netget.set_model(name);
    }
}

// A model is ready and selected: it answers from now on (renderControl hands it the request
// on screen if that is waiting for it, or if the visitor has not begun to answer it). Any
// other WebLLM model still loaded is unloaded (GPU memory is the scarce thing); the built-in
// model's session is kept, it costs nothing.
function activate(m) {
    app.active = m;
    for (const other of app.models) {
        if (other !== m && other.kind === 'webllm' && other.state === 'ready') retireWebLlm(other);
    }
    renderControl();
}

// ---------------------------------------------------------------------------------------
// The model control: one select in the LLM header. The browser's built-in model first where
// it has one, then the WebLLM models, then "You are the model". Choosing a model that is
// already on this device switches to it; one that needs a download shows the one button that
// starts it.
// ---------------------------------------------------------------------------------------

const MODEL_KEY = 'netget-demo-model';
const BUILTIN = 'builtin';
const YOU = 'you';

// Model states: 'checking' (is it already downloaded?), 'loadable' (on this device, loads
// without a click), 'needs-click' (a download the visitor has to ask for), 'loading',
// 'ready', 'failed', 'unsupported' (this browser cannot run it).
function modelById(id) { return app.models.find((m) => m.id === id) || null; }
function selectedModel() { return modelById(app.selected); }

// The full label on a wide screen; on a narrow one only what tells the options apart, so it
// fits the select: "Qwen2.5 3B · 2 GB", "Qwen3 1.7B · thinks · cached".
// Where a model runs, for status lines: "Chrome built-in Gemini Nano", "WebLLM Qwen3 1.7B".
function sourceName(m) {
    return m.kind === BUILTIN ? `${m.where} built-in ${m.name}` : `WebLLM ${m.name}`;
}

function optionLabel(m) {
    if (NARROW.matches) {
        if (m.kind === BUILTIN) return `${m.name} · built in`;
        const bits = [m.name];
        if (m.thinks) bits.push('thinks');
        bits.push(m.state === 'unsupported' ? 'no WebGPU' : m.cached ? 'cached' : m.size.replace(/^~/, ''));
        return bits.join(' · ');
    }
    if (m.kind === BUILTIN) return `${m.name} · ${m.where} built-in`;
    const kind = m.thinks ? 'WebLLM · thinks' : 'WebLLM';
    if (m.state === 'unsupported') return `${m.name} · ${kind} · needs WebGPU`;
    return `${m.name} · ${kind} · ${m.cached ? 'downloaded' : m.size + ' download'}`;
}

function setProgress(fraction) {
    const bar = $('#llm-progress');
    if (fraction === null || fraction === undefined) { bar.hidden = true; return; }
    bar.hidden = false;
    $('#llm-progress-bar').style.width = Math.round(Math.max(0, Math.min(1, fraction)) * 100) + '%';
}

function percent(m) {
    return m.state === 'loading' && typeof m.progress === 'number' ? ` ${Math.round(m.progress * 100)}%` : '';
}

// The select, the button and the status line, from the selected model's state; then who
// answers, and the request on screen routed again.
function renderControl() {
    paintControl();
    renderWho();
    reroute();
}

function paintControl() {
    const sel = $('#model-select');
    for (const opt of sel.options) {
        const m = modelById(opt.value);
        if (m) opt.textContent = optionLabel(m);
    }
    if (app.selected && sel.value !== app.selected) sel.value = app.selected;
    const btn = $('#llm-load');
    const status = $('#llm-status');
    btn.hidden = true;
    btn.disabled = false;
    setProgress(null);
    if (app.selected === YOU) {
        status.textContent = app.models.some((m) => m.state !== 'unsupported')
            ? 'Manual: you write each LLM response.' : 'No local LLM in this browser. Manual responses.';
        return;
    }
    const m = selectedModel();
    if (!m) { status.textContent = 'Manual: you write each LLM response.'; return; }
    const source = sourceName(m);
    const fallback = app.active && app.active !== m ? ` · ${app.active.name} answers meanwhile` : '';
    switch (m.state) {
    case 'ready':
        status.textContent = `Ready: ${source}`;
        break;
    case 'loading': {
        const known = typeof m.progress === 'number';
        setProgress(known ? m.progress : null);
        status.textContent = `${m.verb} ${source}…${percent(m)}${fallback}`;
        break;
    }
    case 'checking':
    case 'loadable':
        status.textContent = `Checking ${source}…${fallback}`;
        break;
    case 'needs-click':
        btn.hidden = false;
        btn.textContent = m.kind === BUILTIN ? 'Download' : `Download · ${m.size}`;
        status.textContent = `${source}: not downloaded${fallback}`;
        break;
    case 'failed':
        btn.hidden = false;
        btn.textContent = 'Retry';
        status.textContent = `${source}: load failed (${m.error || 'unknown error'})${fallback}`;
        break;
    default:
        status.textContent = 'Select an LLM source.';
    }
}

// Switch to `id`: at once if it is loaded, by itself if it is on this device, otherwise the
// button says what the download is. A model answering now keeps answering until then;
// "You are the model" takes over at once, and leaves any loaded model loaded.
function choose(id) {
    if (id === YOU) {
        app.selected = YOU;
        app.active = null;
        renderControl();
        return;
    }
    const m = modelById(id);
    if (!m || m.state === 'unsupported') return;
    app.selected = id;
    if (m.state === 'ready') activate(m);
    else if (m.state === 'loadable') loadModel(m);
    else if (m.state === 'checking') {
        checkWebLlmCache().then(() => {
            if (app.selected === m.id && m.state === 'loadable') loadModel(m);
            else renderControl();
        });
    }
    renderControl();
}

// Must be called synchronously from a gesture handler for a download of the built-in model:
// `create()` checks the activation when it is called, not when it resolves.
function loadModel(m, opts) {
    if (m.kind === BUILTIN) loadBuiltin(m, opts);
    else loadWebLlm(m);
}

async function chromeAvailability() {
    if (!('LanguageModel' in self) || typeof self.LanguageModel.availability !== 'function') return 'unavailable';
    try {
        return await self.LanguageModel.availability(LM_OPTIONS);
    } catch (e) {
        try { return await self.LanguageModel.availability(); } catch (e2) { return 'unavailable'; }
    }
}

// Which model the Prompt API runs is not something the API says. Chrome's is Gemini Nano;
// Edge's is Phi-4-mini (Aion-1.0-Instruct behind an Edge flag, which a page cannot see).
function builtinModel(availability) {
    const edge = /\bEdg\//.test(navigator.userAgent);
    return {
        id: BUILTIN, kind: BUILTIN,
        name: edge ? 'Phi-4-mini' : 'Gemini Nano',
        where: edge ? 'Edge' : 'Chrome',
        availability,
        state: availability === 'available' ? 'loadable' : 'needs-click',
    };
}

async function setupModelControl() {
    const availability = await chromeAvailability();
    const gpu = !!navigator.gpu;
    app.models = [];
    if (availability === 'available' || availability === 'downloadable' || availability === 'downloading') {
        app.models.push(builtinModel(availability));
    }
    for (const w of WEBLLM_MODELS) {
        app.models.push(Object.assign({ kind: 'webllm', cached: false, state: gpu ? 'checking' : 'unsupported' }, w));
    }
    const sel = $('#model-select');
    sel.innerHTML = app.models.map((m) => `<option value="${m.id}"${m.state === 'unsupported' ? ' disabled' : ''}>${escapeHtml(optionLabel(m))}</option>`).join('')
        + `<option value="${YOU}">Respond on behalf of LLM</option>`;
    sel.onchange = () => {
        try { localStorage.setItem(MODEL_KEY, sel.value); } catch (e) { /* storage refused */ }
        choose(sel.value);
    };
    NARROW.addEventListener('change', paintControl);
    $('#llm-load').onclick = () => { const m = selectedModel(); if (m) loadModel(m); };

    // The built-in model's download starts on the visitor's first click or keypress anywhere
    // on the page (Chrome requires a user activation for it), except on the select itself,
    // which is how a visitor says they want a different model.
    const onGesture = (ev) => {
        const m = selectedModel();
        if (!m || m.kind !== BUILTIN || m.state !== 'needs-click') return;
        if (ev.target && ev.target.closest && ev.target.closest('#model-select')) return;
        loadBuiltin(m);
    };
    document.addEventListener('pointerdown', onGesture, { capture: true });
    document.addEventListener('keydown', onGesture, { capture: true });

    let saved = null;
    try { saved = localStorage.getItem(MODEL_KEY); } catch (e) { /* storage refused */ }
    const usable = app.models.filter((m) => m.state !== 'unsupported');
    const initial = saved === YOU ? YOU : (usable.find((m) => m.id === saved) || usable[0] || { id: YOU }).id;
    choose(initial);
    const builtin = modelById(BUILTIN);
    // Already downloading elsewhere: it may not need the activation at all.
    if (builtin && builtin.availability === 'downloading' && app.selected === BUILTIN) loadBuiltin(builtin, { quiet: true });
}

// --- the built-in model (the Prompt API) --------------------------------------------------

function loadBuiltin(m, { quiet = false } = {}) {
    if (m.session || m.creating) return;
    const before = m.state;
    const options = Object.assign({}, LM_OPTIONS, {
        monitor(mon) {
            mon.addEventListener('downloadprogress', (e) => {
                m.state = 'loading';
                m.verb = 'Downloading';
                m.progress = e.loaded;
                if (app.selected === m.id) renderControl();
            });
        },
    });
    let pending;
    try {
        pending = self.LanguageModel.create(options);
    } catch (e) {
        pending = Promise.reject(e);
    }
    m.creating = pending;
    if (!quiet) {
        m.state = 'loading';
        m.verb = before === 'loadable' ? 'Loading' : 'Downloading';
        m.progress = null;
        m.note = null;
        renderControl();
    }
    pending.then((session) => {
        m.creating = null;
        m.session = session;
        m.availability = 'available';
        m.state = 'ready';
        if (app.selected === m.id) activate(m);
        else renderControl();
    }, (e) => {
        m.creating = null;
        if (quiet) { m.state = before; renderControl(); return; }
        console.warn('LanguageModel.create failed', e);
        if (e && e.name === 'NotAllowedError') {
            m.state = 'needs-click';
            m.note = 'The browser wants a click before it downloads the model: press the button.';
        } else {
            m.state = 'failed';
            m.error = String(e && e.message || e);
        }
        renderControl();
    });
}

// --- loading a WebLLM model ---------------------------------------------------------------

function webllmModule() {
    if (app.webllm.module) return Promise.resolve(app.webllm.module);
    if (!app.webllm.importing) {
        app.webllm.importing = import(WEBLLM_URL).then((mod) => {
            app.webllm.module = mod;
            return mod;
        }, (e) => {
            app.webllm.importing = null;
            throw e;
        });
    }
    return app.webllm.importing;
}

// Which WebLLM models this browser already has (WebLLM's own `hasModelInCache`). Loading the
// runtime is the price of asking, so it is only asked once a WebLLM model is selected.
function checkWebLlmCache() {
    if (!app.webllm.checking) {
        app.webllm.checking = (async () => {
            let mod = null;
            try { mod = await webllmModule(); } catch (e) { console.warn('WebLLM runtime did not load', e); }
            await Promise.all(app.models.filter((m) => m.kind === 'webllm').map(async (m) => {
                let cached = false;
                if (mod && typeof mod.hasModelInCache === 'function') {
                    try { cached = await mod.hasModelInCache(m.id); } catch (e) { cached = false; }
                }
                m.cached = !!cached;
                if (m.state === 'checking') m.state = m.cached ? 'loadable' : 'needs-click';
            }));
            // A runtime that failed to load is asked again by the next download.
            if (!mod) app.webllm.checking = null;
        })();
    }
    return app.webllm.checking;
}

async function loadWebLlm(m) {
    if (m.state === 'loading') return;
    m.state = 'loading';
    m.verb = m.cached ? 'Loading' : 'Downloading';
    m.progress = 0;
    renderControl();
    try {
        const mod = await webllmModule();
        const engine = await mod.CreateMLCEngine(m.id, {
            initProgressCallback: (p) => {
                if (typeof p.progress === 'number') m.progress = p.progress;
                if (app.selected === m.id) renderControl();
            },
        }, { context_window_size: WEBLLM_CONTEXT });
        m.cached = true;
        if (app.selected === m.id) {
            m.engine = engine;
            m.state = 'ready';
            activate(m);
        } else {
            // Chosen and then left: it is cached now, and loads by itself if chosen again.
            engine.unload?.();
            m.state = 'loadable';
            renderControl();
        }
    } catch (e) {
        console.error(e);
        m.state = 'failed';
        m.error = String(e && e.message || e);
        renderControl();
    }
}

// Unload a WebLLM engine that no longer answers, once the request it may be in finishes.
function retireWebLlm(m) {
    const engine = m.engine;
    m.engine = null;
    m.state = 'loadable';
    if (!engine) return;
    if (engine.__busy) engine.__retire = true;
    else engine.unload?.();
}

// ---------------------------------------------------------------------------------------
// Requests: one at a time, and only the current one is on screen.
// ---------------------------------------------------------------------------------------

// What a request is about, for a one-line summary: the event id and the line received.
function describe(req) {
    if (req.event) {
        const ctx = req.event.data || {};
        const value = ctx.message ?? ctx.data ?? ctx.line ?? ctx.text;
        return { event: req.event.event_type, detail: typeof value === 'string' ? value : '' };
    }
    const text = req.messages.map((m) => m.content).join('\n');
    const event = (text.match(/Event ID: ([\w.:-]+)/) || [])[1] || null;
    let detail = '';
    const at = text.lastIndexOf('Context data:');
    if (at >= 0) {
        try {
            // The data is pretty-printed JSON, so it holds no blank line; a rule's instruction
            // may follow it after one.
            const ctx = JSON.parse(text.slice(at + 'Context data:'.length).trim().split('\n\n')[0]);
            const v = ctx.message ?? ctx.data ?? ctx.line ?? ctx.text;
            if (typeof v === 'string') detail = v;
        } catch (e) { /* not a JSON object */ }
    }
    if (!event && req.kind === 'chat') {
        const user = [...req.messages].reverse().find((m) => m.role === 'user');
        if (user) detail = user.content.split('\n')[0];
    }
    return { event: event || (req.kind === 'chat' ? 'chat' : req.kind), detail };
}

function handleLlmRequest(json) {
    const req = JSON.parse(json);
    return new Promise((resolve) => {
        // mode: 'waiting' (for a model that is loading), 'manual' (the visitor has it) or
        // 'model' (a model is answering it).
        app.queue.push({ req, resolve, mode: null, touched: false, started: performance.now() });
        pump();
    });
}

function pump() {
    if (app.current || !app.queue.length) { renderQueueCount(); return; }
    app.current = app.queue.shift();
    dispatch(app.current);
}

// `keep`: leave the answered request on screen (a model's answer, with any thinking folded
// away) until the next one replaces it, rather than going idle at once.
function finish(entry, reply, { keep = false } = {}) {
    if (app.current !== entry) return;
    clearTimeout(entry.timer);
    entry.resolve(JSON.stringify(reply));
    app.current = null;
    if (!keep) renderIdle();
    pump();
}

function dispatch(entry) {
    const r = route();
    if (r.to === 'model') answerWithModel(entry);
    else if (r.to === 'wait' && waitLeft(entry) > 0) renderWaiting(entry, r.model);
    else answerManually(entry);
}

function waitLeft(entry) {
    return MODEL_WAIT_MS - (performance.now() - entry.started);
}

// Route the request on screen again after something changed (a model became ready or failed,
// the selection moved, a download started). One a model is answering stays with it. One that
// is waiting goes wherever route() now says. One the visitor has not begun to answer goes to
// a model that is ready, or back to waiting for one that is loading, unless a model already
// failed on it or it already waited its full time.
function reroute() {
    const cur = app.current;
    if (!cur || cur.mode === 'model') return;
    const r = route();
    if (cur.mode === 'waiting') {
        if (r.to === 'model') answerWithModel(cur);
        else if (r.to === 'wait' && r.model === cur.waitFor) updateWaiting(cur);
        else if (r.to === 'wait' && waitLeft(cur) > 0) renderWaiting(cur, r.model);
        else answerManually(cur, leftBy(cur.waitFor));
        return;
    }
    if (cur.mode !== 'manual' || cur.touched || cur.modelFailed) return;
    if (r.to === 'model') answerWithModel(cur);
    else if (r.to === 'wait' && !cur.waitedOut && waitLeft(cur) > 0) renderWaiting(cur, r.model);
}

// Why a request that waited for `m` is the visitor's now.
function leftBy(m) {
    if (app.selected === YOU || !m) return '';
    if (m.state === 'failed') return `${sourceName(m)}: load failed (${m.error || 'unknown error'}). Manual response.`;
    if (m.state === 'needs-click') return `${sourceName(m)}: not downloaded. Manual response.`;
    return '';
}

function renderIdle() {
    $('#llm-current').innerHTML = '<div class="llm-idle">Send a Telnet message to begin.</div>';
}

function renderQueueCount() {
    const el = $('#llm-current .llm-queue');
    if (el) el.textContent = app.queue.length ? `+${app.queue.length} more waiting` : '';
}

function headHtml(entry, state) {
    const { event, detail } = describe(entry.req);
    return `<div class="llm-head">
        <span class="llm-id">#${entry.req.id}</span>
        <span class="llm-kind">${escapeHtml(event)}</span>
        ${detail ? `<span class="llm-meta">“${escapeHtml(detail.length > 80 ? detail.slice(0, 79) + '…' : detail)}”</span>` : ''}
        <span class="llm-state">${escapeHtml(state)}</span>
        <span class="llm-queue"></span>
      </div>`;
}

function promptHtml(req) {
    const n = offeredActions(req).length;
    return `<details class="llm-prompt">
        <summary>The prompt NetGet sent · ${req.messages.length} message${req.messages.length === 1 ? '' : 's'}${n ? ` · ${n} actions offered` : ''}</summary>
        ${req.messages.map((m) => `<span class="llm-role">${escapeHtml(m.role)}</span><pre>${escapeHtml(m.content)}</pre>`).join('')}
      </details>`;
}

// --- waiting for a model that is loading ------------------------------------------------------

function renderWaiting(entry, m) {
    entry.mode = 'waiting';
    entry.waitFor = m;
    clearTimeout(entry.timer);
    entry.timer = setTimeout(() => waitedOut(entry), Math.max(0, waitLeft(entry)));
    const root = $('#llm-current');
    root.innerHTML = headHtml(entry, `waiting for ${m.name}`)
        + '<div class="llm-waiting"><span class="llm-waiting-text"></span></div>'
        + promptHtml(entry.req);
    renderQueueCount();
    updateWaiting(entry);
}

function updateWaiting(entry) {
    const el = $('#llm-current .llm-waiting-text');
    if (!el || app.current !== entry) return;
    const m = entry.waitFor;
    el.textContent = `${m.state === 'loading' ? m.verb : 'Loading'} ${sourceName(m)}…${percent(m)}`;
}

// The model is still not ready: the visitor gets the request, while NetGet still has most of
// its wait left (see MODEL_WAIT_MS). The model takes it back if it is ready before they start.
function waitedOut(entry) {
    if (app.current !== entry || entry.mode !== 'waiting') return;
    entry.waitedOut = true;
    const m = entry.waitFor;
    answerManually(entry, `${sourceName(m)}: still loading after ${MODEL_WAIT_MS / 60000} min. Manual response.`);
}

// --- you are the model -------------------------------------------------------------------

function answerManually(entry, note = '') {
    entry.mode = 'manual';
    clearTimeout(entry.timer);
    const root = $('#llm-current');
    root.innerHTML = headHtml(entry, 'waiting for you')
        + (note ? `<div class="llm-note">${escapeHtml(note)}</div>` : '')
        + '<div class="llm-advanced-only" hidden>' + promptHtml(entry.req) + '</div>'
        + '<div class="llm-composer"></div>';
    renderQueueCount();
    const touch = () => { entry.touched = true; };
    const composerRoot = $('.llm-composer', root);
    for (const type of ['input', 'change', 'click']) composerRoot.addEventListener(type, touch);
    mountComposer(composerRoot, entry.req, {
        autofocus: false,
        onAdvanced: (on) => { $('.llm-advanced-only', root).hidden = !on; },
        onSend: (reply) => { finish(entry, reply); },
        onRefuse: () => { finish(entry, { error: 'refused by the person at the keyboard' }); },
    });
}

// --- a model -------------------------------------------------------------------------------

// The model's output as it is written, in fixed-height blocks that follow the newest line: for
// a model that reasons natively a "Thinking…" block with its think text, which folds to one
// line ("Thought for 3.2 s ▸", which opens it again) once the answer is done; then the answer.
// A model with no thinking of its own shows the answer alone.
function liveView(root, model) {
    const thinks = !!model.thinks;
    root.insertAdjacentHTML('beforeend', (thinks ? `<div class="llm-think" hidden>
        <button type="button" class="llm-think-head" aria-expanded="true">
          <span class="llm-think-label">Thinking…</span><span class="llm-think-caret" aria-hidden="true">▾</span>
        </button>
        <div class="llm-think-body"></div>
      </div>` : '') + `<div class="llm-answer" hidden>
        <div class="llm-answer-label">Answer</div>
        <pre class="llm-answer-body"></pre>
      </div>`);
    const think = $('.llm-think', root);
    const body = $('.llm-think-body', root);
    const answer = $('.llm-answer', root);
    const answerBody = $('.llm-answer-body', root);
    const started = performance.now();
    let text = '';
    let thoughtMs = null;
    const setOpen = (open) => {
        think.classList.toggle('is-collapsed', !open);
        $('.llm-think-head', root).setAttribute('aria-expanded', String(open));
        $('.llm-think-caret', root).textContent = open ? '▾' : '▸';
        if (open) body.scrollTop = body.scrollHeight;
    };
    if (think) $('.llm-think-head', root).addEventListener('click', () => setOpen(think.classList.contains('is-collapsed')));
    const render = (final) => {
        const split = splitThinking(text, { thinks, final });
        if (think && split.thinking) {
            think.hidden = false;
            if (body.textContent !== split.thinking) {
                body.textContent = split.thinking;
                body.scrollTop = body.scrollHeight;
            }
        }
        if (split.thinkingDone && thoughtMs === null) thoughtMs = performance.now() - started;
        const shown = split.answer.trim();
        if (shown) {
            answer.hidden = false;
            if (answerBody.textContent !== shown) {
                answerBody.textContent = shown;
                answerBody.scrollTop = answerBody.scrollHeight;
            }
        }
    };
    return {
        // `full`: everything written so far (not a delta).
        update(full) { text = String(full ?? ''); render(false); },
        done() {
            render(true);
            if (!think) return;
            $('.llm-think-label', root).textContent = `Thought for ${((thoughtMs ?? performance.now() - started) / 1000).toFixed(1)} s`;
            think.classList.add('is-done');
            setOpen(false);
        },
    };
}

async function answerWithModel(entry) {
    entry.mode = 'model';
    clearTimeout(entry.timer);
    const model = app.active;
    const who = model.name;
    const root = $('#llm-current');
    root.innerHTML = headHtml(entry, 'answering')
        + `<div class="llm-working"><span>${escapeHtml(sourceName(model))} generating…</span></div>`;
    renderQueueCount();
    const view = liveView(root, model);
    const started = performance.now();
    let reply;
    const engine = model.kind === BUILTIN ? null : model.engine;
    if (engine) engine.__busy = (engine.__busy || 0) + 1;
    try {
        reply = model.kind === BUILTIN
            ? await answerWithBuiltin(entry.req, model.session, view.update)
            : await answerWithWebLlm(entry.req, engine, model, view.update);
    } catch (e) {
        console.warn('the model could not answer; the visitor answers this one', e);
        if (app.current === entry) {
            entry.modelFailed = true;
            answerManually(entry, `${who} failed: ${e && e.message || e}. Manual response.`);
        }
        return;
    } finally {
        if (engine) {
            engine.__busy -= 1;
            if (!engine.__busy && engine.__retire) engine.unload?.();
        }
    }
    if (app.current !== entry) return;
    view.done();
    $('.llm-working', root)?.remove();
    const state = $('.llm-state', root);
    if (state) state.textContent = `answered in ${((performance.now() - started) / 1000).toFixed(1)} s`;
    finish(entry, reply, { keep: true });
}

// --- the built-in model (the Prompt API) --------------------------------------------------

class UnusableAnswer extends Error {}

// A JSON Schema that only NetGet's action envelope satisfies: `{"actions": [...]}` where each
// item is one of the offered actions, `type` pinned to its name, with exactly that action's
// parameters and nothing else. Tools are left out: they make a small model wander, and
// nothing a tool returns is needed to answer a Telnet line.
//
// `type` is the FIRST property, and that is load-bearing. Constrained decoders (Chrome's, and
// llama.cpp's that Ollama uses) emit an object's properties in the order the schema lists
// them, so the first key decides which branch of the `anyOf` is still open. Every example in
// the prompt starts with "type"; with `type` listed after the parameters, writing it first
// was possible only for the actions with no required parameter (send_telnet_prompt,
// wait_for_more, close_connection), so a model that wanted to answer "hello" was left with
// send_telnet_prompt, and Gemini Nano, llama3.1:8b, qwen2.5:1.5b and gemma3:1b all sent it.
// `additionalProperties: false` is what keeps a key the model half-writes ("prompt셉") out.
function responseConstraint(actions) {
    const items = actions.filter((a) => !a.tool).map((a) => {
        const schema = a.schema && typeof a.schema === 'object' ? a.schema : {};
        const params = Object.assign({}, schema.properties || {});
        delete params.type;
        const properties = Object.assign({ type: { type: 'string', enum: [a.name] } }, params);
        const required = ['type', ...(Array.isArray(schema.required) ? schema.required.filter((r) => r !== 'type' && r in params) : [])];
        return { type: 'object', properties, required, additionalProperties: false };
    });
    return {
        type: 'object',
        properties: { actions: { type: 'array', items: items.length === 1 ? items[0] : { anyOf: items } } },
        required: ['actions'],
    };
}

// The model's text as the reply the composer would have built for the same actions, or an
// UnusableAnswer. Going through the composer's own model is the validation: every action
// must be one offered, every field must build.
function replyFromText(req, actions, text) {
    let parsed;
    try {
        parsed = JSON.parse(text);
    } catch (e) {
        const m = String(text).match(/\{[\s\S]*\}/);
        if (!m) throw new UnusableAnswer('it did not answer with JSON');
        try { parsed = JSON.parse(m[0]); } catch (e2) { throw new UnusableAnswer('it did not answer with JSON'); }
    }
    if (Array.isArray(parsed)) parsed = { actions: parsed };
    if (!parsed || !Array.isArray(parsed.actions)) throw new UnusableAnswer('its answer has no "actions" list');
    const envelope = { actions: [] };
    const tools = [];
    for (const item of [...parsed.actions, ...(Array.isArray(parsed.tools) ? parsed.tools : [])]) {
        const action = item && actions.find((a) => a.name === item.type);
        if (!action) throw new UnusableAnswer(`it chose an action that was not offered (${item && item.type})`);
        (action.tool ? tools : envelope.actions).push(item);
    }
    if (tools.length) envelope.tools = tools;
    const entries = entriesFromEnvelope(actions, envelope);
    if (!entries) throw new UnusableAnswer('its answer does not fit the offered actions');
    const built = buildReply(req, actions, entries);
    if (!built.ok) throw new UnusableAnswer('its answer is missing ' + built.errors.map((e) => e.field).join(', '));
    return built.reply;
}

// The Prompt API's answer to `input`, streamed: `onText` gets everything written so far after
// every chunk. Chrome's promptStreaming() yields deltas; early versions yielded the whole text
// so far each time, which is recognised (a chunk that extends what came before replaces it).
// A session without promptStreaming() answers in one piece through prompt().
async function streamPrompt(session, input, options, onText) {
    if (typeof session.promptStreaming !== 'function') {
        const text = await session.prompt(input, options);
        onText(text);
        return text;
    }
    const stream = await session.promptStreaming(input, options);
    let text = '';
    const take = (chunk) => {
        const piece = String(chunk ?? '');
        text = text && piece.length >= text.length && piece.startsWith(text) ? piece : text + piece;
        onText(text);
    };
    if (stream && typeof stream[Symbol.asyncIterator] === 'function') {
        for await (const chunk of stream) take(chunk);
    } else {
        const reader = stream.getReader();
        for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            take(value);
        }
    }
    return text;
}

async function answerWithBuiltin(req, base, onText) {
    if (!base) throw new Error('the model is not loaded');
    const roles = new Set(['system', 'user', 'assistant']);
    const messages = req.messages.map((m) => ({ role: roles.has(m.role) ? m.role : 'user', content: String(m.content ?? '') }));
    const last = messages.pop() || { role: 'user', content: '' };
    // A fresh conversation per request: NetGet sends the whole context every time.
    const session = messages.length || typeof base.clone !== 'function'
        ? await self.LanguageModel.create(Object.assign({}, LM_OPTIONS, messages.length ? { initialPrompts: messages } : {}))
        : await base.clone();
    try {
        const actions = offeredActions(req);
        if (!actions.length) {
            return { content: await streamPrompt(session, last.content, undefined, onText) };
        }
        const text = await streamPrompt(session, last.content, {
            responseConstraint: responseConstraint(actions),
            // The prompt already describes the envelope and every action.
            omitResponseConstraintInput: true,
        }, onText);
        return replyFromText(req, actions, text);
    } finally {
        session.destroy?.();
    }
}

// --- WebLLM ----------------------------------------------------------------------------------

function toolsAsPrompt(tools) {
    const lines = tools.map((t) => {
        const f = t.function || t;
        return `- ${f.name}: ${f.description || ''}\n  parameters: ${JSON.stringify(f.parameters || {})}`;
    });
    return 'You can call these tools. To call one, reply with ONLY a JSON object of the form '
        + '{"tool_calls":[{"name":"<tool>","arguments":{...}}]} and nothing else. Otherwise reply in plain text.\n\n'
        + lines.join('\n');
}

function parseToolCallsFromText(text) {
    const m = text.match(/\{[\s\S]*"tool_calls"[\s\S]*\}/);
    if (!m) return null;
    try {
        const v = JSON.parse(m[0]);
        if (Array.isArray(v.tool_calls)) {
            return v.tool_calls.map((c) => ({
                name: c.name || c.function?.name,
                arguments: c.arguments ?? c.function?.arguments ?? {},
            }));
        }
    } catch (e) { /* not JSON after all */ }
    return null;
}

function safeJson(v) {
    if (typeof v !== 'string') return v ?? {};
    try { return JSON.parse(v); } catch (e) { return { raw: v }; }
}

// The reply goes back as the model wrote it, less a thinking model's `<think>` block: that is
// cut off (NetGet's own parser, repair and retry take the rest from there, as they would for
// Ollama) and goes as the reply's `reasoning`, which the dashboard shows as it shows an Ollama
// model's thinking. `onText` gets everything written so far after every streamed chunk.
async function answerWithWebLlm(req, engine, model, onText) {
    const messages = req.messages.map((m) => ({ role: m.role, content: m.content }));
    const hasTools = req.tools && req.tools.length;
    const thinks = !!model.thinks;
    // Qwen's own sampling advice for thinking mode is 0.6 (greedy decoding makes it repeat
    // itself), and its thinking comes out of max_tokens. `enable_thinking` is WebLLM 0.2.85's
    // toggle: true (its default, stated here) lets the model think; false prefills an empty
    // `<think></think>` so it answers at once, which splitThinking also handles.
    const base = thinks
        ? { messages, temperature: 0.6, top_p: 0.95, max_tokens: THINKING_MAX_TOKENS, extra_body: { enable_thinking: true } }
        : { messages, temperature: 0.2, max_tokens: 1024 };
    const asked = (text) => {
        const split = splitThinking(text, { thinks, final: true });
        return { split, reasoning: split.thinking || undefined };
    };

    if (hasTools) {
        // Native function calling first (Hermes / Llama 3.1 builds support it); any model
        // gets the tools described in the system prompt as a fallback.
        try {
            const res = await engine.chat.completions.create(Object.assign({}, base, {
                tools: req.tools, tool_choice: 'auto',
            }));
            const msg = res.choices[0].message;
            onText(msg.content || '');
            const { split, reasoning } = asked(msg.content || '');
            return {
                content: split.answer || null,
                reasoning,
                tool_calls: (msg.tool_calls || []).map((c) => ({
                    id: c.id, name: c.function.name,
                    arguments: safeJson(c.function.arguments),
                })),
                prompt_tokens: res.usage?.prompt_tokens || 0,
                completion_tokens: res.usage?.completion_tokens || 0,
            };
        } catch (e) {
            console.warn('WebLLM: native tools unavailable, describing them in the prompt', e);
            const sys = messages.findIndex((m) => m.role === 'system');
            const note = toolsAsPrompt(req.tools);
            if (sys >= 0) messages[sys] = { role: 'system', content: messages[sys].content + '\n\n' + note };
            else messages.unshift({ role: 'system', content: note });
        }
    }

    const streamed = async (opts, before = '') => {
        let text = '';
        let usage = null;
        let finish = null;
        const stream = await engine.chat.completions.create(Object.assign({}, base, opts, { messages, stream: true, stream_options: { include_usage: true } }));
        for await (const chunk of stream) {
            const delta = chunk.choices?.[0]?.delta?.content;
            if (delta) { text += delta; onText(before + text); }
            if (chunk.choices?.[0]?.finish_reason) finish = chunk.choices[0].finish_reason;
            if (chunk.usage) usage = chunk.usage;
        }
        return { text, usage, finish };
    };
    let { text, usage, finish } = await streamed({});
    // A thinking model that spends its whole budget inside `<think>` has no answer. Ask again
    // with thinking off, keeping what it thought on screen: measured on the page with the real
    // Qwen3 1.7B, the Telnet connect event's thinking ran past 2048 tokens (seven minutes at
    // this machine's 5 tokens/s) while every typed line's closed within 400.
    if (thinks && finish === 'length' && !/<\/think>/.test(text)) {
        const thought = splitThinking(text, { thinks, final: true }).thinking;
        const before = `<think>${thought}\n(cut off after ${THINKING_MAX_TOKENS} tokens; answering without thinking)</think>\n`;
        const again = await streamed({ max_tokens: 1024, extra_body: { enable_thinking: false } }, before);
        text = before + again.text;
        usage = again.usage;
    }
    const { split, reasoning } = asked(text);
    const reply = { content: split.answer, reasoning, prompt_tokens: usage?.prompt_tokens || 0, completion_tokens: usage?.completion_tokens || 0 };
    if (hasTools) {
        const calls = parseToolCallsFromText(split.answer);
        if (calls) { reply.tool_calls = calls; reply.content = null; }
    }
    return reply;
}

// ---------------------------------------------------------------------------------------
// The Telnet client: NetGet.connect() on the virtual network, line mode with local echo.
// ---------------------------------------------------------------------------------------

function setTelnetState(text, up) {
    const el = $('#telnet-state');
    el.textContent = text;
    el.classList.toggle('is-up', !!up);
}

// The terminal is a shell session: a prompt, the telnet command, telnet(1)'s own lines, the
// session, and the prompt again when the server hangs up. Enter at the prompt runs the
// command again.
const TELNET_COMMAND = `telnet localhost ${TELNET_PORT}`;
const PROMPT = '$ ';
const TYPE_MS = 40;             // per character of the command, as if typed

function showPrompt() {
    app.telnet.term.write(PROMPT);
}

// Type the command at the prompt, a character at a time; resolves after its Enter.
function typeCommand(msPerChar = TYPE_MS) {
    const t = app.telnet;
    t.typing = true;
    return new Promise((resolve) => {
        let i = 0;
        const tick = () => {
            if (i < TELNET_COMMAND.length) {
                t.term.write(TELNET_COMMAND[i]);
                i += 1;
                setTimeout(tick, msPerChar);
                return;
            }
            t.term.write('\r\n');
            t.typing = false;
            resolve();
        };
        tick();
    });
}

function telnetConnect() {
    const t = app.telnet;
    if (t.conn !== null) { app.netget.close(t.conn); t.conn = null; }
    t.line = '';
    t.term.write('Trying 127.0.0.1...\r\n');
    const decoder = new TelnetDecoder();
    const id = app.netget.connect(TELNET_PORT, (bytes) => {
        const { text, replies } = decoder.push(bytes);
        if (replies.length && t.conn === id) app.netget.send(id, replies);
        if (text) t.term.write(text);
    }, (reason) => {
        const remaining = decoder.finish();
        if (remaining) t.term.write(remaining);
        // Start on a fresh line, as telnet(1) does, without leaving an empty one.
        const nl = t.term.buffer?.active?.cursorX ? '\r\n' : '';
        t.term.write(nl + (reason
            ? `telnet: connect to address 127.0.0.1: ${reason}\r\ntelnet: Unable to connect to remote host\r\n`
            : 'Connection closed by foreign host.\r\n'));
        showPrompt();
        if (t.conn === id) t.conn = null;
        setTelnetState('closed', false);
        if (!app.current) renderIdle();
    });
    t.conn = id;
    t.term.write('Connected to localhost.\r\nEscape character is \'^]\'.\r\n');
    setTelnetState(`connected to :${TELNET_PORT}`, true);
    if (!app.current) renderIdle();
}

// telnet(1) in line mode: the line is edited and echoed here, and sent whole on Enter. At
// the shell prompt, Enter runs the telnet command again.
function telnetInput(d) {
    const t = app.telnet;
    if (t.typing) return;
    if (t.conn === null) {
        if ((d === '\r' || d === '\n') && t.serverUp) typeCommand(TYPE_MS / 2).then(telnetConnect);
        return;
    }
    for (const ch of d.replace(/\x1b\[[0-9;]*[A-Za-z~]|\x1bO./g, '')) {
        if (ch === '\r' || ch === '\n') {
            t.term.write('\r\n');
            app.netget.send(t.conn, enc.encode(t.line + '\r\n'));
            t.line = '';
        } else if (ch === '\x7f' || ch === '\b') {
            if (t.line.length) { t.line = t.line.slice(0, -1); t.term.write('\b \b'); }
        } else if (ch === '\x15') {                   // Ctrl-U: erase the line
            t.term.write('\b \b'.repeat(t.line.length));
            t.line = '';
        } else if (ch >= ' ') {
            t.line += ch;
            t.term.write(ch);
        }
    }
}

function wireTelnet() {
    const term = makeTerm($('#telnet-term'), { cursorBlink: true, scrollback: 500 });
    app.telnet.term = term;
    showPrompt();
    term.onData(telnetInput);
    // xterm.js draws no cursor at all until the terminal is first focused. Mark it drawn (the
    // pinned 5.5.0's coreService flag, which focus() would set) so an unfocused terminal shows
    // the hollow cursor, then focus it unless the visitor has already put focus elsewhere.
    const core = term._core && term._core.coreService;
    if (core && !core.isCursorInitialized) { core.isCursorInitialized = true; term.refresh(0, term.rows - 1); }
    if (!document.activeElement || document.activeElement === document.body) term.focus();
}

// ---------------------------------------------------------------------------------------
// The automatic start: the Telnet server, then the client.
// ---------------------------------------------------------------------------------------

function startTelnetServer(attempt = 0) {
    app.netget.start_server(JSON.stringify({
        protocol: 'telnet', port: TELNET_PORT, instruction: TELNET_INSTRUCTION,
        event_handlers: TELNET_EVENT_HANDLERS,
    }), (json) => {
        const r = JSON.parse(json);
        if (r.error) {
            // The dashboard hands over its status channel a moment after it boots.
            if (/not running yet/.test(r.error) && attempt < 40) { setTimeout(() => startTelnetServer(attempt + 1), 250); return; }
            const banner = $('#demo-banner');
            banner.hidden = false;
            banner.textContent = `Could not open the Telnet server: ${r.error}`;
            return;
        }
        app.telnet.serverId = r.id;
    });
}

function whenListening(port, then, deadline = performance.now() + 15000) {
    if (app.netget.listening_ports().includes(port)) { app.telnet.serverUp = true; then(); return; }
    if (performance.now() > deadline) {
        app.telnet.term.write('Trying 127.0.0.1...\r\ntelnet: connect to address 127.0.0.1: Connection refused\r\ntelnet: Unable to connect to remote host\r\n');
        showPrompt();
        return;
    }
    setTimeout(() => whenListening(port, then, deadline), 100);
}

// ---------------------------------------------------------------------------------------

async function main() {
    const root = $('#demo');
    if (!root) return;
    const banner = $('#demo-banner');
    renderIdle();
    // Which model the control offers does not depend on NetGet; find out while it loads.
    const control = setupModelControl();
    if (!('WebAssembly' in window)) { banner.hidden = false; banner.textContent = 'This browser cannot run WebAssembly.'; return; }

    let mod;
    try {
        mod = await import(PKG);
        await mod.default();
    } catch (e) {
        console.error(e);
        banner.hidden = false;
        banner.innerHTML = 'The demo bundle is not built for this deployment yet. Build it with '
            + '<code>./web/build.sh</code>; see <code>web/README.md</code>.';
        return;
    }

    // xterm.js measures its cell once, when it opens: let the terminal font arrive first.
    await Promise.race([
        document.fonts?.load("13px 'JetBrains Mono'").catch(() => {}),
        new Promise((resolve) => setTimeout(resolve, 3000)),
    ]);
    wireTelnet();
    let netget = null;
    const term = makeTerm($('#dash-term'), {}, (cols, rows) => netget?.resize(cols, rows), { cols: DASH_COLS });
    app.dash = term;
    netget = new mod.NetGet({
        cols: term.cols,
        rows: term.rows,
        model: 'you',
        theme: pageTheme(),
        onOutput: (bytes) => term.write(bytes),
        onLlm: handleLlmRequest,
    });
    app.netget = netget;
    wireDashboardInput(term, netget);
    await control;
    renderWho();

    setTimeout(() => startTelnetServer(), SERVER_AFTER_MS);
    // The command is typed so that it finishes as the client is due to connect.
    const typed = new Promise((resolve) => setTimeout(
        () => typeCommand().then(resolve),
        Math.max(0, CLIENT_AFTER_MS - TELNET_COMMAND.length * TYPE_MS - 100)));
    setTimeout(() => whenListening(TELNET_PORT, () => typed.then(() => {
        telnetConnect();
    })), CLIENT_AFTER_MS);


    $('#theme-toggle')?.addEventListener('click', () => {
        setTimeout(() => { for (const t of [app.dash, app.telnet.term]) t.options.theme = xtermTheme(); }, 0);
    });
}

main();
