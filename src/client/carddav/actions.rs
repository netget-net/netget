use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::dav_common::actions::{action, parameter};
use crate::server::dav_common::{client as engine, server::Kind};
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct CardDavClientProtocol;
impl CardDavClientProtocol {
    pub const fn new() -> Self {
        Self
    }
}

pub static PROTOCOL: CardDavClientProtocol = CardDavClientProtocol;

fn coll() -> crate::llm::actions::Parameter {
    parameter(
        "collection",
        "string",
        "Address book name under the home (as listed on connect) or its absolute path",
        true,
    )
}
fn name() -> crate::llm::actions::Parameter {
    parameter("name", "string", "Object file name, e.g. ada.vcf", true)
}
fn actions() -> Vec<ActionDefinition> {
    vec![
        action("carddav_list", "List a address book's objects with their ETags (PROPFIND Depth 1)", vec![coll()], json!({"type":"carddav_list","collection":"contacts"})),
        action("carddav_get", "Fetch one object (GET)", vec![coll(), name()], json!({"type":"carddav_get","collection":"contacts","name":"ada.vcf"})),
        action(
            "carddav_put",
            "Create or replace an object (PUT); Rust checks the vCard text before sending",
            vec![coll(), name(), parameter("data", "string", "vCard text, e.g. BEGIN:VCARD … VERSION:3.0 … UID … FN … END:VCARD", true), parameter("if_match", "string", "ETag the object must still have (update without overwriting someone else's change)", false), parameter("create_only", "boolean", "Send If-None-Match: * so an existing object is not overwritten", false)],
            json!({"type":"carddav_put","collection":"contacts","name":"ada.vcf","data":"BEGIN:VCARD\r\nVERSION:3.0\r\nUID:ada\r\nFN:Ada Lovelace\r\nEMAIL:ada@example.com\r\nEND:VCARD\r\n","create_only":true}),
        ),
        action("carddav_delete", "Delete an object, or the whole address book when name is omitted", vec![coll(), parameter("name", "string", "Object file name; omit to delete the address book", false), parameter("if_match", "string", "ETag the object must still have", false)], json!({"type":"carddav_delete","collection":"contacts","name":"ada.vcf"})),
        action("carddav_query", "Find cards whose property matches text (addressbook-query REPORT); data comes back with them", vec![coll(), parameter("property", "string", "vCard property to match, e.g. FN or EMAIL (default FN)", false), parameter("text", "string", "Text to look for", true), parameter("match_type", "string", "contains (default), equals, starts-with or ends-with", false)], json!({"type":"carddav_query","collection":"contacts","property":"EMAIL","text":"example.com"})),
        action("carddav_make_collection", "Create a address book under the home (extended MKCOL)", vec![coll(), parameter("displayname", "string", "Display name for the new address book", false)], json!({"type":"carddav_make_collection","collection":"contacts2","displayname":"Second"})),
        action("disconnect", "Stop this CardDAV client", vec![], json!({"type":"disconnect"})),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "carddav_connected",
        "Discovery finished: the principal, the home and its address books",
        json!({"type":"carddav_list","collection":"contacts"}),
    )
    .with_parameters(vec![
        parameter(
            "principal",
            "string",
            "Path of the current user's principal",
            true,
        ),
        parameter("home", "string", "Path of the address book home", true),
        parameter(
            "collections",
            "array",
            "[{href, name, displayname, ctag}] for every address book in the home",
            true,
        ),
    ])
    .with_actions(actions())
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "carddav_response",
        "The server's answer to the last operation",
        json!({"type":"disconnect"}),
    )
    .with_parameters(vec![
        parameter(
            "operation",
            "string",
            "list, get, put, delete, query or make_collection",
            true,
        ),
        parameter(
            "status",
            "number",
            "HTTP status of the answer (207 for list and query)",
            true,
        ),
        parameter(
            "objects",
            "array",
            "For list and query: [{href, name, etag, data (query only)}]",
            false,
        ),
        parameter("data", "string", "For get: the object text", false),
        parameter(
            "etag",
            "string",
            "For get and put: the object's entity tag",
            false,
        ),
        parameter(
            "error",
            "string",
            "For a refused put: the server's error body",
            false,
        ),
    ])
    .with_actions(actions())
});

impl Protocol for CardDavClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "CardDAV"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>WebDAV>CardDAV"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["carddav", "contacts client", "vcard"]
    }
    fn description(&self) -> &'static str {
        "CardDAV client: discovers the user's address books, lists, queries, reads, writes and deletes objects"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), RESPONSE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let p =
            |name: &str, kind: &str, description: &str, example: Value, default: Option<Value>| {
                ParameterDefinition {
                    name: name.into(),
                    type_hint: kind.into(),
                    description: description.into(),
                    required: false,
                    example,
                    default,
                }
            };
        vec![
            p(
                "scheme",
                "string",
                "URL scheme to reach the server with: https (default) or http",
                json!("http"),
                Some(json!(engine::DEFAULT_SCHEME)),
            ),
            p(
                "username",
                "string",
                "User name for HTTP Basic authentication",
                json!("alice"),
                None,
            ),
            p(
                "password",
                "string",
                "Password for HTTP Basic authentication",
                json!("secret"),
                None,
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Shared http_fetch client (reqwest natively, redirects followed by hand for discovery only); RFC 6764 well-known discovery, PROPFIND, addressbook-query REPORT, multistatus parsing, If-Match / If-None-Match, extended MKCOL; objects validated with the server's parser before PUT")
            .llm_control("Which address books and objects to read, query, write or delete")
            .e2e_testing("tests/client/carddav: Radicale 3.8.1 (independent) answers discovery, collection creation, PUT, list, query, GET, conditional PUT and DELETE")
            .notes("No sync-collection or scheduling; one request at a time.")
            .max_inbound_bytes(crate::server::dav_common::xml::MAX_BODY * 4)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Find Ada's email in the CardDAV address book at 127.0.0.1:5232"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"carddav","remote_addr":"127.0.0.1:5232","instruction":"Find everyone at example.com","startup_params":{"scheme":"http","username":"alice","password":"secret"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"carddav_connected","handler":{"type":"static","actions":[{"type":"carddav_list","collection":"contacts"}]}},
            {"event_pattern":"carddav_response","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Client for CardDavClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(engine::connect(ctx, &super::FLAVOR))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        engine::check_action("carddav", Kind::AddressBook, &v)
    }
}
