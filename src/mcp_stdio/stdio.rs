//! Dual-era stdio using rmcp's normal handshake or its direct-serving entry point.
//! Tool routing, task execution, cancellation and JSON-RPC framing remain SDK-owned.

use super::{drain, events, tools::NetGetMcpService};
use futures::StreamExt;
use rmcp::model::{
    ClientNotification, ClientRequest, CustomResult, GetMeta, JsonRpcMessage, ServerResult,
};
use rmcp::service::{NotificationContext, RequestContext, RxJsonRpcMessage, Service};
use rmcp::transport::Transport;
use rmcp::transport::{async_rw::JsonRpcMessageCodec, sink_stream::SinkStreamTransport};
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{FramedRead, FramedWrite};

/// rmcp 1.2's legacy RequestNoParam deserializer drops params._meta. Preserve it
/// before typed decoding so modern ping (including the first request) works.
struct RequestEnvelope(RxJsonRpcMessage<RoleServer>);
impl<'de> serde::Deserialize<'de> for RequestEnvelope {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let meta = value.pointer("/params/_meta").cloned();
        let mut message: RxJsonRpcMessage<RoleServer> =
            serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        if let (JsonRpcMessage::Request(request), Some(meta)) = (&mut message, meta) {
            *request.request.get_meta_mut() =
                serde_json::from_value(meta).map_err(serde::de::Error::custom)?;
        }
        Ok(Self(message))
    }
}

struct FirstMessage<T> {
    first: Option<RxJsonRpcMessage<RoleServer>>,
    inner: T,
}
impl<T: Transport<RoleServer>> Transport<RoleServer> for FirstMessage<T> {
    type Error = T::Error;
    fn send(
        &mut self,
        item: rmcp::service::TxJsonRpcMessage<RoleServer>,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static {
        self.inner.send(item)
    }
    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        if let Some(first) = self.first.take() {
            Some(first)
        } else {
            self.inner.receive().await
        }
    }
    async fn close(&mut self) -> Result<(), Self::Error> {
        self.inner.close().await
    }
}

struct ModernService(NetGetMcpService);
impl Service<RoleServer> for ModernService {
    async fn handle_request(
        &self,
        request: ClientRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<ServerResult, ErrorData> {
        let discover =
            matches!(&request, ClientRequest::CustomRequest(r) if r.method == "server/discover");
        let version = context
            .meta
            .get("io.modelcontextprotocol/protocolVersion")
            .and_then(Value::as_str);
        if context
            .meta
            .get("io.modelcontextprotocol/protocolVersion")
            .is_some_and(|v| !v.is_string())
        {
            return Err(ErrorData::invalid_params(
                "protocolVersion must be a string",
                None,
            ));
        }
        if version.is_some_and(|v| v != events::MODERN_VERSION) {
            return Err(events::error(
                -32022,
                "Unsupported protocol version",
                json!({"supported":[events::MODERN_VERSION],"requested":version}),
            ));
        }
        if !discover {
            let info = context.meta.get("io.modelcontextprotocol/clientInfo");
            let caps = context
                .meta
                .get("io.modelcontextprotocol/clientCapabilities");
            if version.is_none()
                || !info.is_some_and(|v| v["name"].is_string() && v["version"].is_string())
                || !caps.is_some_and(Value::is_object)
            {
                return Err(ErrorData::invalid_params("modern requests require protocolVersion, clientInfo and clientCapabilities in _meta", None));
            }
        }
        let result = self.0.handle_request(request, context).await?;
        let mut value = serde_json::to_value(result)
            .map_err(|_| ErrorData::internal_error("serializing MCP result", None))?;
        value["resultType"] = json!("complete");
        Ok(ServerResult::CustomResult(CustomResult(value)))
    }
    async fn handle_notification(
        &self,
        notification: ClientNotification,
        context: NotificationContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        if matches!(notification, ClientNotification::CancelledNotification(_)) {
            self.0.handle_notification(notification, context).await
        } else {
            Ok(())
        }
    }
    fn get_info(&self) -> rmcp::model::InitializeResult {
        ServerHandler::get_info(&self.0)
    }
}

/// Public for real-wire integration tests; the binary passes actual stdin/stdout.
pub async fn serve<R, W>(service: NetGetMcpService, read: R, write: W) -> anyhow::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let stop = service.event_session.stop.clone();
    let read = FramedRead::new(read, JsonRpcMessageCodec::<RequestEnvelope>::new()).filter_map(
        |message| {
            std::future::ready(match message {
                Ok(message) => Some(message.0),
                Err(error) => {
                    tracing::error!(%error, "invalid MCP input");
                    None
                }
            })
        },
    );
    let write = FramedWrite::new(
        write,
        JsonRpcMessageCodec::<rmcp::service::TxJsonRpcMessage<RoleServer>>::new(),
    );
    let mut transport = drain::DrainOnEof::new(SinkStreamTransport::new(write, read));
    let Some(first) = transport.receive().await else {
        return Ok(());
    };
    let modern = matches!(&first, JsonRpcMessage::Request(r) if
        matches!(&r.request, ClientRequest::CustomRequest(c) if c.method == "server/discover") ||
        r.request.get_meta().contains_key("io.modelcontextprotocol/protocolVersion"));
    let transport = FirstMessage {
        first: Some(first),
        inner: transport,
    };
    if modern {
        rmcp::service::serve_directly(ModernService(service), transport, None)
            .waiting()
            .await?;
    } else {
        service.serve(transport).await?.waiting().await?;
    }
    stop.cancel();
    Ok(())
}
