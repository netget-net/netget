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
