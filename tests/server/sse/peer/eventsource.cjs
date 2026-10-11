// Reads a NetGet event stream with the eventsource package (WHATWG EventSource for Node) and
// prints each event as one JSON line; exits after an event of type `resumed`.
// Usage: node eventsource.cjs <node_modules> <url>
const path = require('path');
const { EventSource } = require(path.join(process.argv[2], 'eventsource'));
const es = new EventSource(process.argv[3]);
const report = (type) => (e) => {
  console.log(JSON.stringify({ type, data: e.data, lastEventId: e.lastEventId }));
  if (type === 'resumed') { es.close(); process.exit(0); }
};
for (const t of ['welcome', 'post', 'resumed', 'message']) es.addEventListener(t, report(t));
es.onerror = () => console.log(JSON.stringify({ type: 'error', readyState: es.readyState }));
setTimeout(() => { console.log(JSON.stringify({ type: 'timeout' })); process.exit(1); }, 60000);
