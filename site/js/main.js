// Copy buttons
document.querySelectorAll('.copy-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
        var code = document.getElementById(btn.getAttribute('data-target'));
        if (!code) return;
        navigator.clipboard.writeText(code.textContent).then(function () {
            btn.textContent = 'Copied!';
            btn.classList.add('copied');
            setTimeout(function () {
                btn.textContent = 'Copy';
                btn.classList.remove('copied');
            }, 2000);
        }).catch(function () {
            btn.textContent = 'Select to copy';
            var selection = window.getSelection();
            var range = document.createRange();
            range.selectNodeContents(code);
            selection.removeAllRanges();
            selection.addRange(range);
        });
    });
    btn.hidden = false;
});

// Light / dark theme toggle
(function () {
    var root = document.documentElement;
    var btn = document.getElementById('theme-toggle');
    if (!btn) return;

    function current() {
        var t = root.getAttribute('data-theme');
        if (t) return t;
        return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }

    function render() {
        btn.textContent = current() === 'light' ? '☾' : '☀';
        btn.setAttribute('aria-label', 'Switch to ' + (current() === 'light' ? 'dark' : 'light') + ' theme');
    }

    btn.addEventListener('click', function () {
        var next = current() === 'light' ? 'dark' : 'light';
        root.setAttribute('data-theme', next);
        try { localStorage.setItem('theme', next); } catch (e) {}
        render();
    });

    render();
    btn.hidden = false;
    window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', render);
})();

// Tabbed code blocks: one panel at a time, and the copy button follows it.
// Blocks marked data-sync="pm" share the package manager: picking pnpm in one
// picks it in the other and rewrites the MCP commands to launch through it.
var MCP_RUNNERS = {
    // yarn dlx logs its install to stdout, which would corrupt MCP's JSON-RPC; -q silences it.
    npm: ['npx', '-y'], pnpm: ['pnpx'], yarn: ['yarn', 'dlx', '-q'], bun: ['bunx']
};

function escapeHtml(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function renderMcp(pm) {
    var runner = MCP_RUNNERS[pm];
    if (!runner) return;
    var command = runner[0];
    var args = runner.slice(1).concat(['@smotana/netget', '--mcp']);
    var line = runner.concat(['@smotana/netget', '--mcp']).join(' ');
    var str = function (v) { return '<span class="str">"' + escapeHtml(v) + '"</span>'; };
    var render = {
        json: function () {
            return '{\n  ' + str('mcpServers') + ': {\n    ' + str('netget') + ': {\n      ' +
                str('command') + ': ' + str(command) + ',\n      ' +
                str('args') + ': [' + args.map(str).join(', ') + ']\n    }\n  }\n}';
        },
        claude: function () { return 'claude mcp add netget -- ' + line; },
        codex: function () { return 'codex mcp add netget -- ' + line; },
        gemini: function () { return 'gemini mcp add netget ' + line; },
        vscode: function () {
            return escapeHtml("code --add-mcp '" + JSON.stringify({ name: 'netget', command: command, args: args }) + "'");
        }
    };
    document.querySelectorAll('code[data-mcp]').forEach(function (code) {
        var fn = render[code.getAttribute('data-mcp')];
        if (fn) code.innerHTML = fn();
    });
}

var pmBlocks = [];

document.querySelectorAll('.code-block.tabs').forEach(function (block) {
    var bar = block.querySelector('.tab-bar');
    var copy = block.querySelector('.copy-btn');
    var panels = block.querySelectorAll('.tab-panel');
    var buttons = [];
    var synced = block.getAttribute('data-sync') === 'pm';

    function select(i) {
        panels.forEach(function (p, j) { p.classList.toggle('active', i === j); });
        buttons.forEach(function (b, j) { b.setAttribute('aria-selected', String(i === j)); });
        if (copy) copy.setAttribute('data-target', panels[i].getAttribute('data-copy') || panels[i].id);
    }

    function selectPm(pm) {
        panels.forEach(function (p, i) { if (p.getAttribute('data-pm') === pm) select(i); });
    }

    panels.forEach(function (panel, i) {
        var b = document.createElement('button');
        b.type = 'button';
        b.setAttribute('role', 'tab');
        b.textContent = panel.getAttribute('data-tab');
        b.addEventListener('click', function () {
            if (!synced) return select(i);
            var pm = panel.getAttribute('data-pm');
            pmBlocks.forEach(function (f) { f(pm); });
            renderMcp(pm);
        });
        bar.appendChild(b);
        buttons.push(b);
    });

    if (synced) pmBlocks.push(selectPm);

    var ua = navigator.userAgent;
    var initial = !block.hasAttribute('data-pick-os') ? 0
        : /Mac/.test(ua) ? 0 : /Fedora/.test(ua) ? 2 : /Linux/.test(ua) ? 1 : 0;
    block.classList.add('js');
    bar.hidden = false;
    select(initial);
});
