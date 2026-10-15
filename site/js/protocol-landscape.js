import { protocolStacks } from './protocol-stacks.js';

const landscape = document.querySelector('.protocol-landscape');

if (landscape) {
    function shuffle(items) {
        const result = [...items];
        for (let i = result.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [result[i], result[j]] = [result[j], result[i]];
        }
        return result;
    }

    const variants = new Map();
    for (const [feature, stack] of protocolStacks) {
        if (!variants.has(feature)) variants.set(feature, []);
        variants.get(feature).push(stack);
    }

    function chooseDriver() {
        // Choose the mode first: LLM 3/9, each other mode 2/9. Adding a script
        // language must not make the script mode more likely.
        const slot = Math.floor(Math.random() * 9);
        if (slot < 3) return 'LLM-driven';
        if (slot < 5) return 'static response';
        if (slot < 7) return 'manual response';
        const languages = ['Python script', 'JavaScript', 'Perl script', 'Go script'];
        return languages[Math.floor(Math.random() * languages.length)];
    }

    // Shuffle once per page load. Resizing preserves the selection and order.
    const selection = shuffle([...variants]).slice(0, 8).map(([feature, stacks]) => ({
        feature,
        stack: stacks[Math.floor(Math.random() * stacks.length)],
        driver: chooseDriver(),
    }));

    const protocolNames = new Map([...document.querySelectorAll('.proto-list a')].map(link => [
        link.title.split(' · protocol: ')[1], link.textContent.trim(),
    ]));

    function layersFor(stack, feature) {
        // A few implementations declare only a broad layer, not a full stack.
        if (['application', 'network', 'Network', 'VPN'].includes(stack)) {
            return [protocolNames.get(feature) || feature];
        }
        if (stack.startsWith('BLUETOOTH_BLE')) {
            const profile = stack.slice('BLUETOOTH_BLE'.length).replaceAll('_', ' ').trim();
            return profile ? ['Bluetooth LE', profile] : ['Bluetooth LE'];
        }
        if (stack.startsWith('USB ')) return ['USB', stack.slice(4)];
        const names = {
            ETH: 'Ethernet', BLE: 'Bluetooth LE', UNIX_SOCKET: 'Unix socket',
            UnixSocket: 'Unix socket', NAMED_PIPE: 'Named pipe', STDIO: 'Standard I/O',
        };
        return stack.split('>').map(layer => names[layer.trim()] || layer.trim());
    }

    function layerClass(layer, index) {
        if (index === 0) return 'stack-link';
        if (['IP', 'IPv4', 'IPv6', 'L2CAP'].includes(layer)) return 'stack-network';
        if (['TCP', 'UDP', 'SCTP', 'QUIC', 'ATT'].includes(layer)) return 'stack-transport';
        return 'stack-application';
    }

    const columns = selection.map(({ feature, stack, driver }) => {
        const column = document.createElement('ol');
        column.className = 'protocol-stack';
        column.dataset.protocol = feature;
        const layers = layersFor(stack, feature);
        column.setAttribute('aria-label', `${driver}: ${[...layers].reverse().join(' over ')}`);
        const badge = document.createElement('li');
        badge.className = 'stack-driver';
        badge.textContent = driver;
        column.append(badge);
        layers.map((layer, index) => {
            const item = document.createElement('li');
            item.className = layerClass(layer, index);
            item.textContent = layer;
            return item;
        }).reverse().forEach(item => column.append(item));
        return column;
    });

    // HTML supplies the initial stacks; CSS fits whole columns with or without JS.
    landscape.replaceChildren(...columns);
}
