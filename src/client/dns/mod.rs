//! DNS client implementation
pub mod actions;

pub use actions::DnsClientProtocol;

use anyhow::{Context, Result};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace};

use crate::client::dns::actions::{
    DNS_CLIENT_CONNECTED_EVENT, DNS_CLIENT_RESPONSE_RECEIVED_EVENT, DNS_CLIENT_ZONE_TRANSFER_EVENT,
    MAX_REPORTED_RECORDS, MAX_TRANSFER_BYTES, MAX_TRANSFER_RECORDS, TRANSFER_TIMEOUT,
};
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::Client;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::{Event, EventType};
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

use hickory_client::client::AsyncClient;
use hickory_client::rr::{Name, RecordType};
use hickory_client::udp::UdpClientStream;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::dnssec::rdata::DNSSECRData;
use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::{RData, Record};
use hickory_proto::xfer::{DnsHandle, DnsRequest, DnsRequestOptions, FirstAnswer};

/// DNS client that connects to a DNS server
pub struct DnsClient;

impl DnsClient {
    /// Connect to a DNS server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // Parse the DNS server address
        let dns_server: SocketAddr = remote_addr
            .parse()
            .context(format!("Invalid DNS server address: {}", remote_addr))?;

        info!("DNS client {} connecting to {}", client_id, dns_server);

        // Create UDP client stream
        let stream = UdpClientStream::<tokio::net::UdpSocket>::new(dns_server);
        let (client, bg) = AsyncClient::connect(stream)
            .await
            .context("Failed to create DNS client")?;

        // Spawn the hickory transport driver. Registered so that stopping the client
        // tears the UDP socket down instead of leaving it running detached.
        let bg_handle = tokio::spawn(async move {
            if let Err(e) = bg.await {
                error!("DNS client {} transport driver stopped: {}", client_id, e);
            }
        });
        app_state.register_client_task(client_id, bg_handle).await;

        // Get local address (best effort)
        let local_addr: SocketAddr = "0.0.0.0:0".parse()?;

        info!("DNS client {} connected to {}", client_id, dns_server);

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] DNS client {} connected to {}",
            client_id, dns_server
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Wrap the hickory client in Arc<Mutex> for sharing across tasks. It lives out here,
        // not inside the conversation task, because the command loop needs the same handle:
        // an injected `send_dns_query` has to go through the one connected resolver, not a
        // second one of its own.
        let client_arc = Arc::new(Mutex::new(client));
        let protocol = Arc::new(DnsClientProtocol::new());

        // Command channel for injected actions (the dashboard's [ send ]).
        //
        // Registered BEFORE the connected-event LLM call below: a dashboard-created client
        // defaults to a `*` -> manual routing rule, so that call can park for minutes waiting
        // for a human, and [ send ] must work for the whole park.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            client_arc.clone(),
            protocol.clone(),
            client_id,
            app_state.clone(),
            llm_client.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Drive the LLM conversation in a registered background task.
        //
        // It used to run inline here, so `connect()` did not return until the LLM
        // stopped asking for queries — and an LLM that never stops asking meant
        // `connect()` never returned. Running it as a tracked task means the caller
        // gets its address immediately and `stop_client` can abort the conversation.
        let conversation_state = app_state.clone();
        let conversation_llm = llm_client.clone();
        let conversation_tx = status_tx.clone();
        let conversation_client = client_arc.clone();
        let conversation_protocol = protocol.clone();
        let handle = tokio::spawn(async move {
            let app_state = conversation_state;
            let llm_client = conversation_llm;
            let status_tx = conversation_tx;
            let client_arc = conversation_client;
            let protocol = conversation_protocol;

            let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
                debug!(
                    "DNS client {} has no instruction; nothing to drive",
                    client_id
                );
                return;
            };

            let event = Event::new(
                &DNS_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "remote_addr": dns_server.to_string(),
                }),
            );

            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &memory,
                Some(&event),
                protocol.as_ref(),
                &status_tx,
            )
            .await
            {
                Ok(ClientLlmResult {
                    actions,
                    memory_updates,
                }) => {
                    // Update memory
                    if let Some(mem) = memory_updates {
                        app_state.set_memory_for_client(client_id, mem).await;
                    }

                    // Drain the initial actions and every follow-up they produce.
                    // Iterative, not recursive — see run_dns_actions.
                    Self::run_dns_actions(
                        &client_arc,
                        &protocol,
                        actions,
                        client_id,
                        &app_state,
                        &llm_client,
                        &status_tx,
                    )
                    .await;
                }
                Err(e) => {
                    error!("LLM error for DNS client {}: {}", client_id, e);
                }
            }

            debug!("DNS client {} conversation task finished", client_id);
        });
        app_state.register_client_task(client_id, handle).await;

        Ok(local_addr)
    }

    /// Execute a batch of DNS actions from the LLM, plus every follow-up action the
    /// LLM produces in response.
    ///
    /// This used to be self-recursive: `execute_dns_action` awaited the LLM, then
    /// called itself for each follow-up action. Because each level is a separately
    /// polled boxed future, stack depth grew with the number of round-trips — a
    /// non-converging LLM loop (see `tests/client/dns`) overflowed the stack after a
    /// couple of hundred queries and took the whole process down, rather than just
    /// stalling the one client.
    ///
    /// It is now an explicit work queue: follow-up actions are pushed onto `pending`
    /// and drained iteratively, so stack depth is constant no matter how many
    /// query/response rounds occur. Convergence itself is enforced separately by the
    /// per-client LLM call budget (`crate::client::llm_budget`), which makes
    /// `call_llm_for_client` start failing once the ceiling is hit and drains this
    /// queue.
    async fn run_dns_actions(
        client: &Arc<Mutex<AsyncClient>>,
        protocol: &Arc<DnsClientProtocol>,
        initial_actions: Vec<serde_json::Value>,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        let mut pending: std::collections::VecDeque<serde_json::Value> =
            initial_actions.into_iter().collect();

        while let Some(action) = pending.pop_front() {
            match Self::execute_dns_action(
                client, protocol, action, client_id, app_state, llm_client, status_tx,
            )
            .await
            {
                Ok(follow_ups) => pending.extend(follow_ups),
                Err(e) => error!("DNS client {} action error: {}", client_id, e),
            }
        }
    }

    /// Execute a single DNS action from the LLM.
    ///
    /// Returns any follow-up actions the LLM asked for; the caller
    /// ([`Self::run_dns_actions`]) queues them. This function never calls itself.
    #[allow(clippy::too_many_arguments)]
    fn execute_dns_action<'a>(
        client: &'a Arc<Mutex<AsyncClient>>,
        protocol: &'a Arc<DnsClientProtocol>,
        action: serde_json::Value,
        client_id: ClientId,
        app_state: &'a Arc<AppState>,
        llm_client: &'a OllamaClient,
        status_tx: &'a mpsc::UnboundedSender<String>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<serde_json::Value>>> + Send + 'a>> {
        Box::pin(async move {
            match Self::apply_dns_action(client, protocol, action, client_id, app_state, status_tx)
                .await?
            {
                DnsApplied::Queried {
                    event_data, event, ..
                } => Ok(Self::report_dns_response(
                    event_data, event, protocol, client_id, app_state, llm_client, status_tx,
                )
                .await),
                DnsApplied::Other(_) => Ok(Vec::new()),
            }
        })
    }

    /// Run one DNS action against the live hickory client, without involving the LLM.
    ///
    /// Split out from [`Self::execute_dns_action`] so the injected-command path can answer
    /// its caller as soon as the resolver replies, and hand the model its
    /// `dns_response_received` event afterwards — a manual routing rule parked on that event
    /// would otherwise hold the dashboard's \[send\] open for its whole timeout.
    async fn apply_dns_action(
        client: &Arc<Mutex<AsyncClient>>,
        protocol: &Arc<DnsClientProtocol>,
        action: serde_json::Value,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<DnsApplied> {
        match protocol.execute_action(action)? {
            crate::llm::actions::client_trait::ClientActionResult::Custom { name, data }
                if name == "dns_query" =>
            {
                let domain = data
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .context("Missing domain in query")?;
                let query_type_str = data
                    .get("query_type")
                    .and_then(|v| v.as_str())
                    .context("Missing query_type")?;
                let recursion_desired = data
                    .get("recursion_desired")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let dnssec = data
                    .get("dnssec")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let name =
                    Name::from_utf8(domain).context(format!("Invalid domain name: {}", domain))?;
                let record_type = Self::parse_record_type(query_type_str)?;
                debug!(
                    "DNS client {} querying {} for {} record (rd={recursion_desired}, \
                     do={dnssec})",
                    client_id, domain, query_type_str
                );

                // Built by hand rather than with `ClientHandle::query`, which fixes RD on and
                // offers no EDNS: `recursion_desired` and `dnssec` both have to reach the wire.
                let mut message = Message::new();
                message
                    .set_id(rand::random::<u16>())
                    .set_message_type(MessageType::Query)
                    .set_op_code(OpCode::Query)
                    .set_recursion_desired(recursion_desired)
                    .add_query(Query::query(name.clone(), record_type));
                let mut edns = Edns::new();
                edns.set_max_payload(1232)
                    .set_version(0)
                    .set_dnssec_ok(dnssec);
                message.set_edns(edns);
                let request = DnsRequest::new(message, DnsRequestOptions::default());
                let response = client.lock().await.send(request).first_answer().await;

                match response {
                    Ok(response) => {
                        let response_code = response.response_code();
                        let answers: Vec<serde_json::Value> =
                            response.answers().iter().filter_map(record_json).collect();
                        let authority: Vec<serde_json::Value> = response
                            .name_servers()
                            .iter()
                            .filter_map(record_json)
                            .collect();
                        trace!(
                            "DNS client {} received response: {} answers, code: {:?}",
                            client_id,
                            answers.len(),
                            response_code
                        );
                        let detail = format!(
                            "dns_query {domain} {query_type_str} -> {} with {} answer(s) \
                                 (hickory owns the wire encoding; no byte count is observable)",
                            Self::response_code_to_string(response_code),
                            answers.len()
                        );
                        let mut event_data = serde_json::json!({
                            "query_id": response.id(),
                            "domain": domain,
                            "query_type": query_type_str,
                            "answers": answers,
                            "response_code": Self::response_code_to_string(response_code),
                            "authenticated_data": response.authentic_data(),
                            "truncated": response.truncated(),
                        });
                        if !authority.is_empty() {
                            event_data["authority"] = serde_json::json!(authority);
                        }
                        Ok(DnsApplied::Queried {
                            event_data,
                            detail,
                            event: &DNS_CLIENT_RESPONSE_RECEIVED_EVENT,
                        })
                    }
                    Err(e) => {
                        error!("DNS client {} query error: {}", client_id, e);
                        Err(anyhow::anyhow!("DNS query failed: {}", e))
                    }
                }
            }
            crate::llm::actions::client_trait::ClientActionResult::Custom { name, data }
                if name == "dns_zone_transfer" =>
            {
                let zone = data
                    .get("zone")
                    .and_then(|v| v.as_str())
                    .context("Missing zone")?;
                let serial = data
                    .get("serial")
                    .and_then(|v| v.as_u64())
                    .map(|s| s as u32);
                let server: SocketAddr = app_state
                    .get_client(client_id)
                    .await
                    .context("the DNS client is gone")?
                    .remote_addr
                    .parse()
                    .context("the DNS client's server address")?;
                let event_data =
                    Self::zone_transfer(server, zone, serial, client_id, app_state).await?;
                let detail = format!(
                    "{} {zone}: {} record(s) in {} message(s)",
                    event_data["transfer_type"].as_str().unwrap_or("XFR"),
                    event_data["record_count"],
                    event_data["messages"]
                );
                Ok(DnsApplied::Queried {
                    event_data,
                    detail,
                    event: &DNS_CLIENT_ZONE_TRANSFER_EVENT,
                })
            }
            crate::llm::actions::client_trait::ClientActionResult::Disconnect => {
                info!("DNS client {} disconnecting", client_id);
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                Ok(DnsApplied::Other("disconnect".to_string()))
            }
            crate::llm::actions::client_trait::ClientActionResult::WaitForMore => {
                debug!("DNS client {} waiting for more", client_id);
                Ok(DnsApplied::Other(
                    "wait_for_more: no query sent".to_string(),
                ))
            }
            other => {
                // Other action results not applicable to DNS
                Ok(DnsApplied::Other(format!(
                    "{other:?} is not a DNS client verb; no query sent"
                )))
            }
        }
    }

    /// Hand one completed query's answers to the model as a `dns_response_received` event
    /// and return whatever follow-up actions it asked for.
    async fn report_dns_response(
        event_data: serde_json::Value,
        event_type: &'static EventType,
        protocol: &Arc<DnsClientProtocol>,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Vec<serde_json::Value> {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return Vec::new();
        };

        let event = Event::new(event_type, event_data);

        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();

        match call_llm_for_client(
            llm_client,
            app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            protocol.as_ref(),
            status_tx,
        )
        .await
        {
            Ok(ClientLlmResult {
                actions,
                memory_updates,
            }) => {
                // Update memory
                if let Some(mem) = memory_updates {
                    app_state.set_memory_for_client(client_id, mem).await;
                }

                // Hand follow-up actions back to the caller's work queue rather than
                // recursing into them here — recursion here is what overflowed the stack.
                actions
            }
            Err(e) => {
                error!("LLM error for DNS client {}: {}", client_id, e);
                Vec::new()
            }
        }
    }

    /// Drain injected commands until the channel closes (the client was removed) or an
    /// injected `disconnect` ends the session.
    ///
    /// A query reports `Executed`, never `Sent`: hickory owns the wire encoding and the
    /// socket, and reports no byte count, so there is no truthful number to hand back. The
    /// detail string carries the response code and answer count instead, which is what the
    /// caller actually wants to see.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        client: Arc<Mutex<AsyncClient>>,
        protocol: Arc<DnsClientProtocol>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let is_disconnect = action.get("type").and_then(|v| v.as_str()) == Some("disconnect");

            // A completed query is reported to the model only after the caller has been
            // answered, so `queried` carries the event payload past the reply.
            let mut queried: Option<(serde_json::Value, &'static EventType)> = None;
            let outcome = match Self::apply_dns_action(
                &client,
                &protocol,
                action.clone(),
                client_id,
                &app_state,
                &status_tx,
            )
            .await
            {
                Ok(DnsApplied::Queried {
                    event_data,
                    detail,
                    event,
                }) => {
                    queried = Some((event_data, event));
                    Ok(ClientSendOutcome::Executed { detail })
                }
                Ok(DnsApplied::Other(_)) if is_disconnect => Ok(ClientSendOutcome::Disconnected),
                Ok(DnsApplied::Other(detail)) => Ok(ClientSendOutcome::Executed { detail }),
                // `execute_action` failing and the query itself failing are different
                // things: the first is the model naming a verb this client does not have,
                // the second is a network fault. Only the first is a Rejected.
                Err(e) if e.to_string().starts_with("Unknown DNS client action") => {
                    Ok(ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    })
                }
                Err(e) => Err(e),
            };

            let outcome_json = match &outcome {
                Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
                Err(e) => serde_json::json!({"error": e.to_string()}),
            };
            app_state
                .record_access_log(
                    AccessLogOwner::Client(client_id.as_u32()),
                    protocol.protocol_name(),
                    None,
                    "injected_action",
                    action,
                    vec![outcome_json],
                )
                .await;

            let disconnect = matches!(outcome, Ok(ClientSendOutcome::Disconnected));
            if let Err(e) = &outcome {
                error!("DNS client {} injected action failed: {}", client_id, e);
                let _ = status_tx.send(format!(
                    "[WARN] Client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                break;
            }

            if let Some((event_data, event)) = queried {
                let follow_ups = Self::report_dns_response(
                    event_data,
                    event,
                    &protocol,
                    client_id,
                    &app_state,
                    &llm_client,
                    &status_tx,
                )
                .await;
                Self::run_dns_actions(
                    &client,
                    &protocol,
                    follow_ups,
                    client_id,
                    &app_state,
                    &llm_client,
                    &status_tx,
                )
                .await;
            }
        }

        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Parse DNS record type from string
    fn parse_record_type(type_str: &str) -> Result<RecordType> {
        match type_str.to_uppercase().as_str() {
            "A" => Ok(RecordType::A),
            "AAAA" => Ok(RecordType::AAAA),
            "ANAME" => Ok(RecordType::ANAME),
            "CAA" => Ok(RecordType::CAA),
            "CNAME" => Ok(RecordType::CNAME),
            "MX" => Ok(RecordType::MX),
            "NAPTR" => Ok(RecordType::NAPTR),
            "NS" => Ok(RecordType::NS),
            "OPENPGPKEY" => Ok(RecordType::OPENPGPKEY),
            "PTR" => Ok(RecordType::PTR),
            "SOA" => Ok(RecordType::SOA),
            "SRV" => Ok(RecordType::SRV),
            "SSHFP" => Ok(RecordType::SSHFP),
            "TLSA" => Ok(RecordType::TLSA),
            "TXT" => Ok(RecordType::TXT),
            _ => Err(anyhow::anyhow!("Unsupported DNS record type: {}", type_str)),
        }
    }

    /// Convert ResponseCode to string
    fn response_code_to_string(code: ResponseCode) -> String {
        match code {
            ResponseCode::NoError => "NOERROR".to_string(),
            ResponseCode::FormErr => "FORMERR".to_string(),
            ResponseCode::ServFail => "SERVFAIL".to_string(),
            ResponseCode::NXDomain => "NXDOMAIN".to_string(),
            ResponseCode::NotImp => "NOTIMP".to_string(),
            ResponseCode::Refused => "REFUSED".to_string(),
            ResponseCode::YXDomain => "YXDOMAIN".to_string(),
            ResponseCode::YXRRSet => "YXRRSET".to_string(),
            ResponseCode::NXRRSet => "NXRRSET".to_string(),
            ResponseCode::NotAuth => "NOTAUTH".to_string(),
            ResponseCode::NotZone => "NOTZONE".to_string(),
            _ => format!("{:?}", code),
        }
    }
}

impl DnsClient {
    /// AXFR, or IXFR from `serial`, over a TCP connection of its own (the query client is UDP).
    /// The records are counted and bounded at [`MAX_TRANSFER_RECORDS`], the messages' bytes at
    /// [`MAX_TRANSFER_BYTES`], the whole exchange at [`TRANSFER_TIMEOUT`]. Only the first
    /// [`MAX_REPORTED_RECORDS`] are kept and reported, so a large zone is a count and a sample
    /// rather than an event the model cannot read, and memory does not grow with the zone.
    ///
    /// The messages are read straight off the socket, one length-prefixed message at a time,
    /// rather than through hickory's multiplexer, which hands responses over with `try_send`
    /// into a 32-slot channel and drops what does not fit: a transfer read that way could lose
    /// messages and still look complete. Read here, a slow reader only slows the server down
    /// (TCP backpressure), and [`XfrEnd`] decides where the transfer ends as hickory does.
    async fn zone_transfer(
        server: SocketAddr,
        zone: &str,
        serial: Option<u32>,
        _client_id: ClientId,
        _app_state: &Arc<AppState>,
    ) -> Result<serde_json::Value> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let origin = Name::from_utf8(zone).with_context(|| format!("invalid zone {zone:?}"))?;
        // IXFR names the serial the client holds in an SOA; the other fields are not read.
        let last_soa = serial.map(|s| SOA::new(origin.clone(), origin.clone(), s, 0, 0, 0, 0));
        let transfer_type = if last_soa.is_some() { "IXFR" } else { "AXFR" };
        let mut request =
            hickory_proto::op::update_message::zone_transfer(origin.clone(), last_soa.clone());
        let id: u16 = rand::random();
        request.set_id(id);
        let wire = request
            .to_vec()
            .context("cannot encode the transfer request")?;
        let request_len =
            u16::try_from(wire.len()).context("the transfer request does not fit one message")?;

        // The first MAX_REPORTED_RECORDS records; `record_count` counts every one.
        let mut records: Vec<Record> = Vec::new();
        let mut record_count = 0usize;
        let mut bytes_received = 0usize;
        let mut messages = 0usize;
        let mut rcode = ResponseCode::NoError;
        let mut end = XfrEnd::new(last_soa.is_some());
        let exchange = async {
            let mut stream = tokio::net::TcpStream::connect(server)
                .await
                .with_context(|| {
                    format!("cannot open a TCP connection to {server} for the transfer")
                })?;
            stream.write_all(&request_len.to_be_bytes()).await?;
            stream.write_all(&wire).await?;
            loop {
                let mut len = [0u8; 2];
                match stream.read_exact(&mut len).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => anyhow::bail!(
                        "{transfer_type} of {zone}: the server closed the connection before the \
                         transfer ended"
                    ),
                    Err(e) => return Err(e.into()),
                }
                let len = usize::from(u16::from_be_bytes(len));
                bytes_received = bytes_received.saturating_add(len + 2);
                if bytes_received > MAX_TRANSFER_BYTES {
                    anyhow::bail!(
                        "{transfer_type} of {zone} passed {MAX_TRANSFER_BYTES} bytes; abandoned"
                    );
                }
                let mut body = vec![0u8; len];
                stream.read_exact(&mut body).await?;
                let response = Message::from_vec(&body)
                    .map_err(|e| anyhow::anyhow!("{transfer_type} failed: {e}"))?;
                if response.id() != id {
                    anyhow::bail!(
                        "{transfer_type} of {zone}: a message answered id {} where {id} was asked",
                        response.id()
                    );
                }
                messages += 1;
                rcode = response.response_code();
                if rcode != ResponseCode::NoError {
                    break;
                }
                let answers = response.answers();
                record_count = record_count.saturating_add(answers.len());
                let room = MAX_REPORTED_RECORDS.saturating_sub(records.len());
                records.extend(answers.iter().take(room).cloned());
                if record_count > MAX_TRANSFER_RECORDS {
                    anyhow::bail!(
                        "{transfer_type} of {zone} passed {MAX_TRANSFER_RECORDS} records; abandoned"
                    );
                }
                end.process(answers)
                    .map_err(|e| anyhow::anyhow!("{transfer_type} of {zone}: {e}"))?;
                if end.ended() {
                    break;
                }
            }
            Ok::<(), anyhow::Error>(())
        };
        tokio::time::timeout(TRANSFER_TIMEOUT, exchange)
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "{transfer_type} of {zone} did not finish within {}s",
                    TRANSFER_TIMEOUT.as_secs()
                )
            })??;

        let serial_now = records.first().and_then(|r| match r.data() {
            Some(RData::SOA(s)) => Some(s.serial()),
            _ => None,
        });
        // RFC 1995 §4: an incremental answer's second record is an SOA (the old serial); a
        // full one's is not. A single SOA says the client is current.
        let form = match (transfer_type, record_count) {
            (_, 0) => "none",
            ("IXFR", 1) => "current",
            ("IXFR", _) if records.get(1).map(|r| r.record_type()) == Some(RecordType::SOA) => {
                "incremental"
            }
            _ => "full",
        };
        let reported: Vec<serde_json::Value> = records.iter().filter_map(record_json).collect();
        Ok(serde_json::json!({
            "zone": origin.to_string(),
            "transfer_type": transfer_type,
            "form": form,
            "response_code": Self::response_code_to_string(rcode),
            "serial": serial_now,
            "record_count": record_count,
            "messages": messages,
            "records": reported,
            "truncated": record_count > MAX_REPORTED_RECORDS,
        }))
    }
}

/// Where an AXFR or IXFR ends, decided from the answers in order: hickory-client 0.24's
/// `ClientStreamXfrState`, without the stream it wraps. The first record's SOA serial is the
/// one the transfer closes on. An AXFR ends at the next SOA; a second SOA with the same serial
/// is an empty zone. An IXFR (RFC 1995) alternates old and new SOAs and ends on an even count
/// of them whose last carries the expected serial.
#[derive(Debug)]
pub enum XfrEnd {
    Start { maybe_incr: bool },
    Second { maybe_incr: bool, expected: u32 },
    Axfr { expected: u32 },
    Ixfr { even: bool, expected: u32 },
    Ended,
}

impl XfrEnd {
    pub fn new(maybe_incr: bool) -> Self {
        XfrEnd::Start { maybe_incr }
    }

    pub fn ended(&self) -> bool {
        matches!(self, XfrEnd::Ended)
    }

    /// Takes one message's answers in order; `Err` for a transfer that cannot be valid.
    pub fn process(&mut self, answers: &[Record]) -> Result<(), &'static str> {
        fn serial(r: &Record) -> Option<u32> {
            r.data().and_then(RData::as_soa).map(SOA::serial)
        }
        if answers.is_empty() {
            return Ok(());
        }
        match std::mem::replace(self, XfrEnd::Ended) {
            XfrEnd::Start { maybe_incr } => match serial(&answers[0]) {
                Some(expected) => {
                    *self = XfrEnd::Second {
                        maybe_incr,
                        expected,
                    };
                    self.process(&answers[1..])
                }
                None => Err("the transfer does not start with the zone's SOA"),
            },
            XfrEnd::Second {
                maybe_incr,
                expected,
            } => match serial(&answers[0]) {
                Some(s) if s == expected => {
                    if answers.len() == 1 {
                        Ok(())
                    } else {
                        Err("invalid zone transfer, contains trailing records")
                    }
                }
                Some(_) if maybe_incr => {
                    *self = XfrEnd::Ixfr {
                        even: true,
                        expected,
                    };
                    self.process(&answers[1..])
                }
                Some(_) => Err("invalid zone transfer, expected AXFR, got IXFR"),
                None => {
                    *self = XfrEnd::Axfr { expected };
                    self.process(&answers[1..])
                }
            },
            XfrEnd::Axfr { expected } => {
                let soas = answers
                    .iter()
                    .filter(|a| a.record_type() == RecordType::SOA)
                    .count();
                match soas {
                    0 => {
                        *self = XfrEnd::Axfr { expected };
                        Ok(())
                    }
                    1 if answers.last().map(|r| r.record_type()) == Some(RecordType::SOA) => Ok(()),
                    _ => Err("invalid zone transfer, contains trailing records"),
                }
            }
            XfrEnd::Ixfr { even, expected } => {
                let even = answers
                    .iter()
                    .fold(even, |even, a| even ^ (a.record_type() == RecordType::SOA));
                let last_is_expected = answers.last().and_then(serial) == Some(expected);
                if !(even && last_is_expected) {
                    *self = XfrEnd::Ixfr { even, expected };
                }
                Ok(())
            }
            XfrEnd::Ended => Ok(()),
        }
    }
}

/// A record type's mnemonic, or RFC 3597's `TYPE<n>` for one hickory has no name for.
fn type_name(t: RecordType) -> String {
    match t {
        RecordType::Unknown(n) => format!("TYPE{n}"),
        other => other.to_string(),
    }
}

/// One record as the model reads it. DNSSEC records are reported structurally — what a
/// signature covers and which key made it — never as base64.
fn record_json(record: &Record) -> Option<serde_json::Value> {
    let data = record.data()?;
    let mut v = match data {
        RData::A(a) => serde_json::json!({"type": "A", "ip": a.to_string()}),
        RData::AAAA(a) => serde_json::json!({"type": "AAAA", "ip": a.to_string()}),
        RData::CNAME(c) => serde_json::json!({"type": "CNAME", "target": c.to_string()}),
        RData::MX(mx) => serde_json::json!({
            "type": "MX",
            "exchange": mx.exchange().to_string(),
            "preference": mx.preference(),
        }),
        RData::TXT(txt) => {
            let text: Vec<String> = txt
                .iter()
                .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                .collect();
            serde_json::json!({"type": "TXT", "text": text.join("")})
        }
        RData::NS(ns) => serde_json::json!({"type": "NS", "nameserver": ns.to_string()}),
        RData::SOA(soa) => serde_json::json!({
            "type": "SOA",
            "mname": soa.mname().to_string(),
            "rname": soa.rname().to_string(),
            "serial": soa.serial(),
            "refresh": soa.refresh(),
            "retry": soa.retry(),
            "expire": soa.expire(),
            "minimum": soa.minimum(),
        }),
        RData::PTR(ptr) => serde_json::json!({"type": "PTR", "domain": ptr.to_string()}),
        RData::SRV(srv) => serde_json::json!({
            "type": "SRV",
            "priority": srv.priority(),
            "weight": srv.weight(),
            "port": srv.port(),
            "target": srv.target().to_string(),
        }),
        RData::DNSSEC(DNSSECRData::RRSIG(sig)) => serde_json::json!({
            "type": "RRSIG",
            "type_covered": type_name(sig.type_covered()),
            "algorithm": u8::from(sig.algorithm()),
            "key_tag": sig.key_tag(),
            "signer": sig.signer_name().to_string(),
            "inception": sig.sig_inception(),
            "expiration": sig.sig_expiration(),
        }),
        RData::DNSSEC(DNSSECRData::DNSKEY(key)) => serde_json::json!({
            "type": "DNSKEY",
            "flags": key.flags(),
            "algorithm": u8::from(key.algorithm()),
            "key_tag": key.calculate_key_tag().ok(),
            "secure_entry_point": key.secure_entry_point(),
        }),
        RData::DNSSEC(DNSSECRData::NSEC(nsec)) => serde_json::json!({
            "type": "NSEC",
            "next": nsec.next_domain_name().to_string(),
            "types": nsec.type_bit_maps().iter().map(|t| type_name(*t)).collect::<Vec<_>>(),
        }),
        RData::DNSSEC(DNSSECRData::DS(ds)) => serde_json::json!({
            "type": "DS",
            "key_tag": ds.key_tag(),
            "algorithm": u8::from(ds.algorithm()),
            "digest_type": u8::from(ds.digest_type()),
        }),
        // A type this client does not read: named, sized, never shown as encoded bytes.
        _ => serde_json::json!({
            "type": type_name(record.record_type()),
            "rdata_length": hickory_proto::serialize::binary::BinEncodable::to_bytes(data)
                .map(|b| b.len())
                .unwrap_or_default(),
        }),
    };
    v["name"] = serde_json::json!(record.name().to_string());
    v["ttl"] = serde_json::json!(record.ttl());
    Some(v)
}

/// What [`DnsClient::apply_dns_action`] did with one action.
enum DnsApplied {
    /// A query completed. `event_data` is the `dns_response_received` payload the model
    /// still has to be shown; `detail` summarises it for the injecting caller.
    Queried {
        event_data: serde_json::Value,
        detail: String,
        /// `dns_response_received` for a query, `dns_zone_transfer_received` for a transfer.
        event: &'static EventType,
    },
    /// The action ran but sent no query; the string says why.
    Other(String),
}
