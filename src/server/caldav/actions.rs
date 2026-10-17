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
pub struct CalDavProtocol;
impl CalDavProtocol {
    pub const fn new() -> Self {
        Self
    }
}

pub static PROTOCOL: CalDavProtocol = CalDavProtocol;
pub static LOGIN_EVENT: LazyLock<EventType> =
    LazyLock::new(|| dav::login_event("caldav", engine::Kind::Calendar));
pub static REQUEST_EVENT: LazyLock<EventType> =
    LazyLock::new(|| dav::request_event("caldav", engine::Kind::Calendar));
pub static FLAVOR: engine::Flavor = engine::Flavor {
    kind: engine::Kind::Calendar,
    name: "CalDAV",
    prefix: "caldav",
    root: "calendars",
    well_known: "/.well-known/caldav",
    extension: "ics",
    login_event: &LOGIN_EVENT,
    request_event: &REQUEST_EVENT,
    protocol: &PROTOCOL,
};

impl Protocol for CalDavProtocol {
    fn protocol_name(&self) -> &'static str {
        "CalDAV"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>WebDAV>CalDAV"
    }
    fn description(&self) -> &'static str {
        "CalDAV calendar server (RFC 4791): discovery, calendars, event and task CRUD, calendar-query and multiget REPORTs"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["caldav", "calendar", "ical", "icalendar"]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        dav::sync_actions("caldav", engine::Kind::Calendar)
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
            .implementation("hyper HTTP/1.1; RFC 6764 well-known redirect, principals and calendar homes, PROPFIND (allprop, propname, named props), MKCALENDAR, PROPPATCH, calendar-query (comp-filter, time-range, prop-filter, text-match) and calendar-multiget evaluated by Rust over handler data; iCalendar validated on PUT")
            .llm_control("Logins and every calendar and object: what exists, what a put or delete does")
            .e2e_testing("tests/server/caldav: python caldav 3.3.1 and vdirsyncer 0.21.0 (independent) discover, create calendars, put, search by time range, update with ETags and delete")
            .notes("Recurring components are not expanded: a time-range query treats a recurring object as running from its first start onward. No sync-collection, scheduling (RFC 6638), ACLs or free-busy reports. No storage: the handler owns every calendar and object.")
            .request_only("CalDAV answers each HTTP request; push and sync-collection are not offered")
            .answers_on_failure()
            .max_inbound_bytes(crate::server::dav_common::xml::MAX_BODY)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "CalDAV server with a Work calendar holding this week's meetings"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"caldav","port":5232,"instruction":"A calendar server with a work calendar","startup_params":{"auth":"none"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"caldav_request","handler":{"type":"static","actions":[{"type":"caldav_collections","collections":[{"name":"work"}]}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\na={'type':'caldav_collections','collections':[{'name':'work'}]} if e['operation']=='list_collections' else ({'type':'caldav_objects','objects':[]} if e['operation']=='list_objects' else {'type':'caldav_error','status':404})\nprint(json.dumps({'actions':[a]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Server for CalDavProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(engine::spawn(ctx, &FLAVOR))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        dav::check_answer("caldav", &v)?;
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
