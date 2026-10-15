// The "you are the model" composer: answer a model request by picking actions and filling
// in their parameters, instead of hand-writing the JSON envelope.
//
// NetGet sends every offered action with the request (`req.actions`, built by
// `netget::llm::bridge::offered_action`): name, description, parameters with their declared
// types, a JSON Schema, and the action's own example — which its executor accepts. Every
// field starts from that example, so the common case is pick → tweak → send.
//
// It is modelled on the dashboard's intercept composer (src/tui/modal/composer.rs). The
// reply it builds is the one the plain textarea produced: `{content: '{"actions":[...]}'}`,
// with tools under `"tools"`, or native `tool_calls` for a chat request that carries tool
// schemas. The form is the only editor for requests with offered actions.
//
// The top half of this file is pure (no DOM) so web/test/smoke.mjs can build the same reply
// under Node and check that NetGet accepts it.

// ---------------------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------------------

/** The actions a request offers; empty when the request (or an older bundle) has none. */
export function offeredActions(req) {
    return Array.isArray(req && req.actions) ? req.actions.filter((a) => a && a.name) : [];
}

/** Which action to preselect: the first one specific to this protocol and event. */
export function defaultActionIndex(actions) {
    const i = actions.findIndex((a) => !a.generic && !a.tool);
    return i >= 0 ? i : 0;
}

const NUMBER_HINT = /^(number|integer|int|float|double|u8|u16|u32|u64|usize|i8|i16|i32|i64|isize)$/i;

/**
 * How a parameter is edited: 'choice' | 'bool' | 'number' | 'json' | 'text'.
 * The example's value decides when there is one (it is known to be accepted); otherwise
 * the declared type hint does.
 */
export function fieldKind(param, exampleValue) {
    if (Array.isArray(param.choices) && param.choices.length) return 'choice';
    if (exampleValue !== undefined && exampleValue !== null) {
        if (typeof exampleValue === 'boolean') return 'bool';
        if (typeof exampleValue === 'number') return 'number';
        if (typeof exampleValue === 'object') return 'json';
        return 'text';
    }
    const hint = String(param.type || '').trim();
    if (/bool/i.test(hint)) return 'bool';
    if (NUMBER_HINT.test(hint)) return 'number';
    if (/array|object|map|list|\[|\{/i.test(hint)) return 'json';
    return 'text';
}

function exampleOf(action) {
    return action && action.example && typeof action.example === 'object' && !Array.isArray(action.example)
        ? action.example : {};
}

/**
 * One action being composed. `fields` holds the raw editor value of each parameter:
 * text → string, number → string, bool → true/false/null (null = not sent),
 * choice → string ('' = not sent), json → string. `extras` are keys the example carries
 * that no parameter declares; they are sent as the example has them.
 */
export function newEntry(action, source) {
    const values = source && typeof source === 'object' ? source : exampleOf(action);
    const declared = new Set((action.parameters || []).map((p) => p.name));
    const fields = (action.parameters || []).map((param) => {
        const v = values[param.name];
        const kind = fieldKind(param, v === undefined ? exampleOf(action)[param.name] : v);
        let raw;
        if (kind === 'bool') raw = v === undefined ? (param.required ? false : null) : v === true || v === 'true';
        else if (kind === 'choice') raw = v === undefined ? (param.required ? param.choices[0] : '') : String(v);
        else if (kind === 'json') raw = v === undefined ? '' : JSON.stringify(v, null, 2);
        else if (kind === 'number') raw = v === undefined ? '' : String(v);
        else raw = v === undefined ? '' : (typeof v === 'string' ? v : JSON.stringify(v));
        // A string that carries CRLF is edited in a textarea, which normalises line breaks to
        // LF; remember to put them back.
        const crlf = kind === 'text' && typeof v === 'string' && v.includes('\r\n');
        return { name: param.name, kind, raw, crlf, required: !!param.required };
    });
    const extras = Object.create(null);
    for (const [k, v] of Object.entries(values)) {
        if (k !== 'type' && !declared.has(k)) extras[k] = v;
    }
    return { name: action.name, fields, extras };
}

/**
 * The one field the simple composer edits: the index of the entry's only parameter when it is
 * free text (send_telnet_line's `line`), otherwise -1 and the full form is the only editor.
 */
export function simpleFieldIndex(entry) {
    return entry && entry.fields.length === 1 && entry.fields[0].kind === 'text' ? 0 : -1;
}

/**
 * The action object an entry stands for: `{ok: true, value}` or `{ok: false, errors}`,
 * where each error is `{field, message}`.
 */
export function buildAction(entry) {
    const value = Object.create(null);
    value.type = entry.name;
    const errors = [];
    for (const f of entry.fields) {
        switch (f.kind) {
        case 'bool':
            if (f.raw !== null) value[f.name] = !!f.raw;
            break;
        case 'choice':
            if (f.raw !== '') value[f.name] = f.raw;
            break;
        case 'number': {
            const s = String(f.raw).trim();
            if (s === '') { if (f.required) errors.push({ field: f.name, message: 'required' }); break; }
            const n = Number(s);
            if (!Number.isFinite(n)) errors.push({ field: f.name, message: 'not a number' });
            else if (Number.isInteger(n) && !Number.isSafeInteger(n)) errors.push({ field: f.name, message: 'integer is too large to represent exactly' });
            else value[f.name] = n;
            break;
        }
        case 'json': {
            const s = String(f.raw).trim();
            if (s === '') { if (f.required) errors.push({ field: f.name, message: 'required' }); break; }
            try { value[f.name] = JSON.parse(s); } catch (e) { errors.push({ field: f.name, message: 'not valid JSON: ' + e.message }); }
            break;
        }
        default: {
            if (f.raw === '' && !f.required) break;
            value[f.name] = f.crlf ? String(f.raw).replace(/\r\n/g, '\n').replace(/\n/g, '\r\n') : f.raw;
        }
        }
    }
    Object.assign(value, entry.extras);
    return errors.length ? { ok: false, errors } : { ok: true, value };
}

/** `{actions:[...]}` plus `tools:[...]` when any entry is a tool. */
export function buildEnvelope(actions, entries) {
    const envelope = { actions: [] };
    const tools = [];
    for (const entry of entries) {
        const built = buildAction(entry);
        if (!built.ok) return { ok: false, entry, errors: built.errors };
        const action = actions.find((a) => a.name === entry.name);
        (action && action.tool ? tools : envelope.actions).push(built.value);
    }
    if (tools.length) envelope.tools = tools;
    return { ok: true, envelope };
}

/**
 * The reply NetGet's bridge takes for these entries. A chat request that carries native tool
 * schemas is answered with `tool_calls` when every entry is one of those tools; everything
 * else, and an empty answer, is the JSON envelope as `content`.
 */
export function buildReply(req, actions, entries) {
    const built = buildEnvelope(actions, entries);
    if (!built.ok) return built;
    const toolNames = new Set((req.tools || []).map((t) => (t.function && t.function.name) || t.name));
    if (req.kind === 'chat' && entries.length && entries.every((e) => toolNames.has(e.name))) {
        const calls = [...(built.envelope.tools || []), ...built.envelope.actions].map((v) => {
            const { type, ...args } = v;
            return { name: type, arguments: args };
        });
        return { ok: true, reply: { content: null, tool_calls: calls } };
    }
    return { ok: true, reply: { content: JSON.stringify(built.envelope) } };
}

/** Entries for a parsed envelope, or null if the form cannot show it faithfully. */
export function entriesFromEnvelope(actions, parsed) {
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    const known = new Set(Object.keys(parsed));
    known.delete('actions'); known.delete('tools');
    if (known.size) return null;
    if (Object.hasOwn(parsed, 'actions') && !Array.isArray(parsed.actions)) return null;
    if (Object.hasOwn(parsed, 'tools') && !Array.isArray(parsed.tools)) return null;
    const items = [...(parsed.tools || []), ...(parsed.actions || [])];
    const entries = [];
    for (const item of items) {
        const action = item && actions.find((a) => a.name === item.type);
        if (!action) return null;
        const entry = newEntry(action, item);
        const built = buildAction(entry);
        if (!built.ok || !sameJson(built.value, item)) return null;
        entries.push(entry);
    }
    // A tool put under actions (or vice versa) cannot survive the form's categorization.
    const rebuilt = buildEnvelope(actions, entries).envelope;
    if (!sameJson(rebuilt.actions, parsed.actions || []) || !sameJson(rebuilt.tools || [], parsed.tools || [])) return null;
    return entries;
}

function sameJson(left, right) {
    if (left === right) return true;
    if (!left || !right || typeof left !== 'object' || typeof right !== 'object') return false;
    if (Array.isArray(left) !== Array.isArray(right)) return false;
    const keys = Object.keys(left);
    return keys.length === Object.keys(right).length
        && keys.every((key) => Object.hasOwn(right, key) && sameJson(left[key], right[key]));
}

// ---------------------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------------------

function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function oneLine(text, max = 70) {
    const first = String(text || '').split(/\n|(?<=\.)\s/)[0].trim();
    return first.length > max ? first.slice(0, max - 1) + '…' : first;
}

let uid = 0;

/**
 * Render the composer into `root` and resolve through `onSend(reply)` / `onRefuse()`.
 *
 * When the preselected action takes one free-text parameter, the composer starts simple: one
 * textarea holding `prefill` (or the action's example), Send, and Advanced, which opens the
 * full form (any action, any number of them, answer with nothing, refuse). `onAdvanced(on)`
 * reports each switch, including the initial one. Falls back to a plain reply field when the
 * request offers no actions. `autofocus: false` leaves the focus wherever the visitor put it;
 * focusing never scrolls the page.
 */
export function mountComposer(root, req, { onSend, onRefuse, onAdvanced = () => {}, prefill = '', autofocus = true }) {
    const actions = offeredActions(req);
    const id = 'cmp' + (++uid);
    const state = {
        entries: actions.length ? [newEntry(actions[defaultActionIndex(actions)])] : [],
    };
    const simpleAction = actions.length ? actions[defaultActionIndex(actions)] : null;
    const simpleField = simpleFieldIndex(state.entries[0]);
    const canSimple = simpleField >= 0;
    // An example that ends its text with a line break (send_telnet_message's "Hello\r\n") is
    // a line: the simple field shows it without the break and puts it back on send.
    const lineBreak = canSimple && /\n$/.test(String(state.entries[0].fields[simpleField].raw));
    const shown = (text) => (lineBreak ? String(text).replace(/\r?\n$/, '') : String(text));

    root.innerHTML = `
      ${canSimple ? `<div class="cmp-simple"><textarea class="llm-input cmp-simple-input" rows="2" spellcheck="false" aria-label="${esc(simpleAction.parameters[simpleField].name)} (${esc(simpleAction.name)})"></textarea></div>` : ''}
      <div class="cmp-form" id="${id}-form"></div>
      ${actions.length ? '' : `<textarea class="llm-input cmp-free-input" rows="8" spellcheck="false" aria-label="Reply"></textarea>`}
      <div class="cmp-error" role="alert"></div>
      <div class="llm-actions">
        <button type="button" class="btn btn-primary llm-send">Send</button>
        <button type="button" class="btn cmp-nothing cmp-adv" title='Reply {"actions": []}: a real answer that does nothing, not a failure'>Answer with nothing</button>
        <button type="button" class="btn llm-fail cmp-adv">Refuse (fail closed)</button>
        ${canSimple ? '<button type="button" class="btn cmp-toggle" aria-expanded="false">Advanced</button>' : ''}
      </div>
    `;

    const formEl = root.querySelector('.cmp-form');
    const freeInput = root.querySelector('.cmp-free-input');
    const simpleInput = root.querySelector('.cmp-simple-input');
    const toggle = root.querySelector('.cmp-toggle');
    const errorEl = root.querySelector('.cmp-error');
    let advanced = !canSimple;

    const growSimple = () => {
        simpleInput.style.height = 'auto';
        simpleInput.style.height = simpleInput.scrollHeight + 2 + 'px';
    };

    // The simple field's text as the one entry it stands for.
    function simpleEntries() {
        const entry = newEntry(simpleAction);
        const text = simpleInput.value;
        entry.fields[simpleField].raw = lineBreak && !text.endsWith('\n') ? text + '\n' : text;
        return [entry];
    }

    function setAdvanced(on) {
        if (on && !advanced) {
            state.entries = simpleEntries();
            renderForm();
        } else if (!on && advanced) {
            const first = state.entries[0];
            if (first && first.name === simpleAction.name) simpleInput.value = shown(first.fields[simpleField].raw);
        }
        advanced = on;
        paintMode();
    }

    function paintMode() {
        const on = advanced;
        errorEl.textContent = '';
        root.querySelector('.cmp-simple').hidden = on;
        formEl.hidden = !on;
        for (const b of root.querySelectorAll('.cmp-adv')) b.hidden = !on;
        toggle.textContent = on ? 'Simple' : 'Advanced';
        toggle.setAttribute('aria-expanded', String(on));
        if (!on) growSimple();
        onAdvanced(on);
    }

    function renderField(entry, ei, f, fi, action) {
        const param = action.parameters[fi];
        const fid = `${id}-e${ei}-f${fi}`;
        const descId = fid + '-d';
        const req = f.required ? '<span class="cmp-req" aria-hidden="true">*</span>' : '';
        const common = `id="${fid}" data-ei="${ei}" data-fi="${fi}" aria-describedby="${descId}"${f.required ? ' aria-required="true"' : ''}`;
        let control;
        switch (f.kind) {
        case 'bool':
            control = `<input type="checkbox" ${common}${f.raw ? ' checked' : ''}>`;
            break;
        case 'choice': {
            const choices = f.raw !== '' && !param.choices.includes(f.raw) ? [...param.choices, f.raw] : param.choices;
            control = `<select ${common}>${f.required ? '' : `<option value=""${f.raw === '' ? ' selected' : ''}>(not sent)</option>`}${choices.map((c) => `<option${c === f.raw ? ' selected' : ''}>${esc(c)}</option>`).join('')}</select>`;
            break;
        }
        case 'number':
            control = `<input type="number" step="any" ${common} value="${esc(f.raw)}">`;
            break;
        case 'json':
            control = `<textarea rows="${Math.min(8, Math.max(2, String(f.raw).split('\n').length))}" spellcheck="false" class="cmp-json" ${common}>${esc(f.raw)}</textarea>`;
            break;
        default:
            control = /[\r\n]/.test(f.raw) || String(f.raw).length > 60
                ? `<textarea rows="${Math.min(6, Math.max(2, String(f.raw).split('\n').length))}" spellcheck="false" ${common}>${esc(f.raw)}</textarea>`
                : `<input type="text" spellcheck="false" ${common} value="${esc(f.raw)}">`;
        }
        const crlf = f.kind === 'text' && /[\r\n]/.test(f.raw)
            ? `<label class="cmp-crlf"><input type="checkbox" data-crlf data-ei="${ei}" data-fi="${fi}"${f.crlf ? ' checked' : ''}> send line breaks as CRLF</label>` : '';
        const unset = f.kind === 'bool' && !f.required
            ? `<button type="button" class="cmp-unset" data-unset data-ei="${ei}" data-fi="${fi}"${f.raw === null ? ' hidden' : ''}>don't send</button>` : '';
        const notSent = f.kind === 'bool' && f.raw === null ? ' <em class="cmp-dim">(not sent)</em>' : '';
        return `
          <div class="cmp-field cmp-kind-${f.kind}">
            <label for="${fid}"><code>${esc(f.name)}</code>${req} <span class="cmp-type">${esc(param.type)}</span>${notSent}</label>
            <div class="cmp-control">${control}${unset}${crlf}</div>
            <div class="cmp-desc" id="${descId}">${esc(param.description || '')}<span class="cmp-field-error"></span></div>
          </div>`;
    }

    function renderForm() {
        if (!actions.length) { formEl.innerHTML = ''; return; }
        formEl.innerHTML = state.entries.map((entry, ei) => {
            const action = actions.find((a) => a.name === entry.name);
            const extras = Object.keys(entry.extras);
            return `
              <fieldset class="cmp-entry" data-ei="${ei}">
                <legend>Action ${ei + 1}</legend>
                <div class="cmp-pick">
                  <label for="${id}-e${ei}-pick" class="cmp-sr">Action ${ei + 1}</label>
                  <select id="${id}-e${ei}-pick" class="cmp-picker" data-ei="${ei}" aria-describedby="${id}-e${ei}-about">
                    ${actions.map((a) => `<option value="${esc(a.name)}"${a.name === entry.name ? ' selected' : ''}>${esc(a.name)}${a.tool ? ' (tool)' : ''} — ${esc(oneLine(a.description))}</option>`).join('')}
                  </select>
                  ${state.entries.length > 1 ? `<button type="button" class="btn cmp-remove" data-ei="${ei}" aria-label="Remove action ${ei + 1}">Remove</button>` : ''}
                </div>
                <p class="cmp-about" id="${id}-e${ei}-about">${esc(action.description || '')}</p>
                ${entry.fields.length ? entry.fields.map((f, fi) => renderField(entry, ei, f, fi, action)).join('') : '<p class="cmp-dim">No parameters.</p>'}
                ${extras.length ? `<p class="cmp-dim">Also sends ${extras.map((k) => `<code>${esc(k)}</code>`).join(', ')} from the example.</p>` : ''}
                <details class="cmp-schema">
                  <summary>Schema and example</summary>
                  <pre>${esc(JSON.stringify(action.schema ?? {}, null, 2))}</pre>
                  <pre>${esc(JSON.stringify(action.example ?? {}, null, 2))}</pre>
                </details>
              </fieldset>`;
        }).join('') + '<button type="button" class="btn cmp-add">+ Add another action</button>';
    }

    function fieldAt(el) {
        const entry = state.entries[+el.dataset.ei];
        return entry && entry.fields[+el.dataset.fi];
    }

    function showFieldError(ei, fi, message) {
        const input = formEl.querySelector(`[data-ei="${ei}"][data-fi="${fi}"]:not([data-crlf]):not([data-unset])`);
        if (!input) return;
        input.setAttribute('aria-invalid', message ? 'true' : 'false');
        const slot = input.closest('.cmp-field').querySelector('.cmp-field-error');
        slot.textContent = message ? ' — ' + message : '';
        return input;
    }

    formEl.addEventListener('input', (ev) => {
        const el = ev.target;
        if (el.dataset.crlf !== undefined) { const f = fieldAt(el); if (f) f.crlf = el.checked; return; }
        if (el.dataset.fi === undefined) return;
        const f = fieldAt(el);
        if (!f) return;
        if (f.kind === 'bool') {
            f.raw = el.checked;
            const unset = el.closest('.cmp-field').querySelector('[data-unset]');
            if (unset) unset.hidden = false;
            const em = el.closest('.cmp-field').querySelector('label em');
            if (em) em.remove();
        } else {
            f.raw = el.value;
        }
        errorEl.textContent = '';
        if (f.kind === 'json' || f.kind === 'number') {
            const probe = buildAction({ name: '', fields: [f], extras: {} });
            showFieldError(el.dataset.ei, el.dataset.fi, probe.ok ? '' : probe.errors[0].message);
        }
    });
    formEl.addEventListener('change', (ev) => {
        const el = ev.target;
        if (el.classList.contains('cmp-picker')) {
            const action = actions.find((a) => a.name === el.value);
            state.entries[+el.dataset.ei] = newEntry(action);
            renderForm();
            formEl.querySelector(`#${id}-e${el.dataset.ei}-pick`).focus();
        } else if (el.tagName === 'SELECT' && el.dataset.fi !== undefined) {
            const f = fieldAt(el);
            if (f) f.raw = el.value;
        } else if (el.type === 'checkbox' && el.dataset.fi !== undefined && el.dataset.crlf === undefined) {
            // Safari fires only `change` for checkboxes.
            const f = fieldAt(el);
            if (f && f.kind === 'bool' && f.raw !== el.checked) el.dispatchEvent(new Event('input', { bubbles: true }));
        }
    });
    formEl.addEventListener('click', (ev) => {
        const el = ev.target.closest('button');
        if (!el) return;
        if (el.classList.contains('cmp-add')) {
            state.entries.push(newEntry(actions[defaultActionIndex(actions)]));
            renderForm();
            formEl.querySelector(`#${id}-e${state.entries.length - 1}-pick`).focus();
        } else if (el.classList.contains('cmp-remove')) {
            state.entries.splice(+el.dataset.ei, 1);
            renderForm();
            formEl.querySelector('.cmp-picker')?.focus();
        } else if (el.dataset.unset !== undefined) {
            const f = fieldAt(el);
            if (f) { f.raw = null; renderForm(); }
        }
    });

    function send() {
        errorEl.textContent = '';
        if (freeInput) { onSend({ content: freeInput.value }); return; }
        if (!advanced) {
            const built = buildReply(req, actions, simpleEntries());
            if (built.ok) onSend(built.reply);
            else errorEl.textContent = built.errors.map((e) => e.field + ' ' + e.message).join('; ');
            return;
        }
        const built = buildReply(req, actions, state.entries);
        if (!built.ok) {
            const ei = state.entries.indexOf(built.entry);
            let first = null;
            for (const err of built.errors) {
                const fi = built.entry.fields.findIndex((f) => f.name === err.field);
                first = first || showFieldError(ei, fi, err.message);
            }
            errorEl.textContent = `Action ${ei + 1}: ${built.errors.map((e) => e.field + ' ' + e.message).join('; ')}`;
            first?.focus();
            return;
        }
        onSend(built.reply);
    }

    root.querySelector('.llm-send').addEventListener('click', send);
    root.querySelector('.cmp-nothing').addEventListener('click', () => onSend({ content: JSON.stringify({ actions: [] }) }));
    root.querySelector('.llm-fail').addEventListener('click', () => onRefuse());
    root.addEventListener('keydown', (ev) => {
        if ((ev.metaKey || ev.ctrlKey) && ev.key === 'Enter') { ev.preventDefault(); send(); }
    });

    if (canSimple) {
        simpleInput.value = prefill || shown(state.entries[0].fields[simpleField].raw);
        simpleInput.addEventListener('input', growSimple);
        // Enter sends, as a chat box does; Shift+Enter is a line break.
        simpleInput.addEventListener('keydown', (ev) => {
            if (ev.key === 'Enter' && !ev.shiftKey && !ev.metaKey && !ev.ctrlKey && !ev.isComposing) { ev.preventDefault(); send(); }
        });
        toggle.addEventListener('click', () => setAdvanced(!advanced));
        paintMode();
        if (autofocus) simpleInput.focus({ preventScroll: true });
    } else if (actions.length) {
        renderForm();
        onAdvanced(true);
        if (autofocus) formEl.querySelector('.cmp-picker')?.focus({ preventScroll: true });
    } else {
        onAdvanced(true);
        formEl.hidden = true;
        freeInput.addEventListener('input', () => {
            freeInput.style.height = 'auto';
            freeInput.style.height = freeInput.scrollHeight + 2 + 'px';
        });
        if (autofocus) freeInput.focus({ preventScroll: true });
    }
}
