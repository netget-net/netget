# NSQ client

Feature `nsq`, canonical name NSQ, TCP/4150. No new dependencies. Uses the existing
server's pure V2 command/frame codec and Tokio TCP. Primary references:
https://nsq.io/clients/tcp_protocol_spec.html
https://github.com/nsqio/nsq/blob/v1.3.0/nsqd/protocol_v2.go
https://github.com/nsqio/nsq/blob/v1.3.0/nsqd/client_v2.go

Connect sends V2 magic and feature-negotiating IDENTIFY automatically. The configurable
`heartbeat_interval_ms` is 1000..60000, default 30000. Output buffering is disabled using
nsqd's supported `output_buffer_size=-1`; TLS/compression are not requested. The client
fails explicitly if negotiation indicates auth_required, TLS or compression, or if the
negotiation is malformed. No AUTH, lookupd discovery, automatic reconnect or TLS support.

`nsq_request` supports publish/PUB, publish_many/MPUB, publish_deferred/DPUB,
subscribe/SUB, ready/RDY, finish/FIN, requeue/REQ, touch/TOUCH, close/CLS and nop/NOP.
Bodies are UTF-8 strings with byte lengths computed by Rust. Names and message IDs are
validated before writing. Subscribe once, then set ready; ready zero pauses delivery.
RDY is the simultaneous in-flight ceiling in nsqd 1.3.0: FIN/REQ free a slot without
requiring another RDY. The prose protocol page's decrement-per-delivery statement does
not describe that daemon's implementation, so this client follows the pinned source and
independent daemon evidence.
Reducing RDY cannot retract messages already selected or in transit. The client bounds
in-flight IDs by the largest RDY grant on this connection, so a late delivery after
RDY0 remains acknowledgeable without falsely rejecting the peer.

Events: `nsq_connected` after IDENTIFY, `nsq_response` for OK/CLOSE_WAIT,
`nsq_message` with topic/channel/id/timestamp/attempts/body and byte count, `nsq_error`
with code/description/fatal and a pending request if correlated. RDY/FIN/REQ/TOUCH/NOP
have no success reply. Error frames for FIN/REQ/TOUCH are asynchronous and may be
uncorrelated; all other errors close. There is no automatic FIN. Binary incoming
messages have null body, body_utf8=false and an exact body_bytes count; the model can
still decide FIN/REQ/TOUCH by ID. Outbound binary payloads are outside the action scope.
CLS returns CLOSE_WAIT and stops new selections; it leaves the socket available to
acknowledge messages already in flight until an explicit disconnect. In nsqd 1.3.0,
StartClose changes RDY/state without synchronizing the message pump's selected branch
with the writer lock. One already-selected delivery can therefore follow CLOSE_WAIT.
The client admits at most one such late message within the prior RDY concurrency bound;
a second late delivery is refused even if FIN freed a slot.

The command handle is registered before IDENTIFY and before a manual connected handler.
Three owned tasks: one continuous frame reader, one I/O session, one event dispatcher.
The reader's partial frame cannot be cancelled by polling an action; the session answers
heartbeats even while the dispatcher waits for a human. Event/frame/action queues are
bounded at 16, maximum response data is 1 MiB plus the 26-byte message header, single
outgoing messages at most 1 MiB, MPUB at most 1024 messages and body at most 5 MiB, RDY at most 2500, delays at
most 3600000 ms. Partial frames, response-producing commands and writes have 15 s
deadlines. Idle server silence is bounded by twice the requested heartbeat plus 1 s.
Command injection can disconnect during a pending read or write; other writes may be
rejected busy. At most one response-producing command is pending; handler actions wait
for its response. Response followups stop at depth 4; fresh delivery events reset depth.
Common memory actions run through shared client routing, and memory_updates is applied
when the handler result provides it. All tasks abort on client removal. Final events
drain after EOF; the dispatcher owns no socket. Only in-flight IDs are retained for flow
validation; the client stores no queue, application data or protocol-private persistence.

Maturity remains Experimental. Tests use independent nsqd 1.3.0, deterministic and
mocked model decisions, the existing NetGet broker pair, framing/semantic negatives,
followup bounds, heartbeats and cleanup. No NSQ Wireshark dissector or pcap oracle is
claimed. Existing server peers are the upstream to_nsq/nsq_tail tools.

Batching is On: deliveries (and responses/errors) raised while the model answers wait in the
dispatcher queue (16); with batching on the dispatcher drains everything waiting into one
`call_llm_for_client_batch` call, one event each, with it off one event per call. Every
`nsq_message` carries its own `message_id`, so a batched answer still finishes, requeues or
touches each delivery by id; there is still no automatic FIN. A batch's follow-ups are as deep
as its deepest event. `tests/client/nsq/batching_test.rs` is the off/on pair.
