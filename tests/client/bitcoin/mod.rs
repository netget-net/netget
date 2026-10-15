// `e2e_test` additionally needs `http`, and that is not pedantry: both of its tests stand a
// NetGet **HTTP** server up as the Bitcoin RPC node (`"base_stack": "HTTP"`), because Bitcoin
// Core's RPC is JSON-RPC over HTTP and there is no Bitcoin *server* protocol to point at.
// `bitcoin = ["dep:bitcoin"]` pulls in no such thing, so at `--features bitcoin` alone these
// compiled happily and then failed at runtime with `Protocol 'HTTP' exists but is not compiled
// into this build` — which reads exactly like the target-directory contention artefact the
// root CLAUDE.md warns about, and is not. Gating on both makes the requirement true at compile
// time instead of discovering it in a test log.
mod e2e_test;

// `command_channel_test` stands up its own `tokio::net::TcpListener` and writes the HTTP
// response by hand, so it needs nothing but `bitcoin`.
mod command_channel_test;

// `rpc_auth_test` stands up its own raw TCP stub node, so it needs nothing but `bitcoin`.
mod rpc_auth_test;
