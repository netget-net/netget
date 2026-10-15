# opcua selected scope

async-opcua 0.19.0 (MPL-2.0), with the bounded-task patch documented in
github.com/netget-net/async-opcua (NETGET.md; published as netget-async-opcua-*). Only anonymous SecurityPolicy None /
MessageSecurityMode None endpoints are declared. Use within trusted test networks.
Namespace urn:netget:device exposes Device, writable Double Value and Method with
one Double input/output; browse the namespace array instead of assuming its index.
Read, write and method operations call handlers; no device values persist.
Subscriptions report the initial handler value and approved-write notifications;
they do not periodically sample externally changing handler values.
Client supports scalar double/boolean/int32/uint32/string, forward browse capped
at 100 references (truncated reported), read/write/call and up to ten subscriptions.
No history, events, secure policies or node management. 256 TCP connections,
20 sessions, 64 pending services per connection, 256KiB messages, 10-second handler
and client deadlines. Client socket address is unavailable from upstream API.
Actions: opcua_reply; client opcua_browse,opcua_read,opcua_write,opcua_call,
opcua_subscribe. Independent asyncua 1.1.8 checks both roles.

See tests/helpers/ICS_PEERS.md for reproducible independent peers.
