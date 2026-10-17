use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{EventType, SpawnContext};
use crate::server::dav_common::{actions as dav, server as engine};
use crate::state::app_state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct CardDavProtocol;
impl CardDavProtocol {
    pub const fn new() -> Self {
        Self
    }
}

pub static PROTOCOL: CardDavProtocol = CardDavProtocol;
pub static LOGIN_EVENT: LazyLock<EventType> =
    LazyLock::new(|| dav::login_event("carddav", engine::Kind::AddressBook));
pub static REQUEST_EVENT: LazyLock<EventType> =
    LazyLock::new(|| dav::request_event("carddav", engine::Kind::AddressBook));
pub static FLAVOR: engine::Flavor = engine::Flavor {
    kind: engine::Kind::AddressBook,
    name: "CardDAV",
    prefix: "carddav",
    root: "addressbooks",
    well_known: "/.well-known/carddav",
    extension: "vcf",
    login_event: &LOGIN_EVENT,
    request_event: &REQUEST_EVENT,
    protocol: &PROTOCOL,
};

impl Protocol for CardDavProtocol {
    fn protocol_name(&self) -> &'static str {
        "CardDAV"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>WebDAV>CardDAV"
    }
    fn description(&self) -> &'static str {
        "CardDAV address book server (RFC 6352): discovery, address books, vCard CRUD, addressbook-query and multiget REPORTs"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["carddav", "contacts", "vcard", "address book"]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        dav::sync_actions("carddav", engine::Kind::AddressBook)
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![LOGIN_EVENT.clone(), REQUEST_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        dav::startup_parameters(engine::DEFAULT_USER, engine::DEFAULT_AUTH)
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("hyper HTTP/1.1; RFC 6764 well-known redirect, principals and address-book homes, PROPFIND, extended MKCOL, PROPPATCH, addressbook-query (prop-filter, text-match, anyof/allof, limit) and addressbook-multiget evaluated by Rust over handler data; vCard validated on PUT")
            .llm_control("Logins and every address book and object: what exists, what a put or delete does")
            .e2e_testing("tests/server/carddav: vdirsyncer 0.21.0 (independent) discovers, uploads, updates and deletes vCards; raw REPORTs and the NetGet pair")
            .notes("No sync-collection, ACLs or vCard conversion between versions. No storage: the handler owns every address book and card.")
            .request_only("CardDAV answers each HTTP request; push and sync-collection are not offered")
            .answers_on_failure()
            .max_inbound_bytes(crate::server::dav_common::xml::MAX_BODY)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "CardDAV server with a Contacts address book of three people"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"carddav","port":5233,"instruction":"An address book server with a contacts book","startup_params":{"auth":"none"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"carddav_request","handler":{"type":"static","actions":[{"type":"carddav_collections","collections":[{"name":"contacts"}]}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\na={'type':'carddav_collections','collections':[{'name':'contacts'}]} if e['operation']=='list_collections' else ({'type':'carddav_objects','objects':[]} if e['operation']=='list_objects' else {'type':'carddav_error','status':404})\nprint(json.dumps({'actions':[a]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Server for CardDavProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(engine::spawn(ctx, &FLAVOR))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        dav::check_answer("carddav", &v)?;
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
