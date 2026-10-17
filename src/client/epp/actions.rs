use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::epp::actions::{action, parameter};
use crate::server::epp::xml::{el, escape, CONTACT, DOMAIN, EPP, HOST};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct EppClientProtocol;
impl EppClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn object_param() -> crate::llm::actions::Parameter {
    parameter("object", "string", "domain, host or contact", true)
}

fn defs() -> Vec<ActionDefinition> {
    vec![
        action(
            "epp_login",
            "Log in (when the client was not configured to log in by itself)",
            vec![
                parameter("client_id", "string", "The registrar's clID", true),
                parameter("password", "string", "The registrar's EPP password", true),
            ],
            json!({"type": "epp_login", "client_id": "ClientX", "password": "foo-BAR2"}),
        ),
        action(
            "epp_check",
            "Check whether names (domain, host) or ids (contact) are available",
            vec![
                object_param(),
                parameter("names", "array", "Up to 64 names or ids", true),
            ],
            json!({"type": "epp_check", "object": "domain", "names": ["example.com", "example.net"]}),
        ),
        action(
            "epp_info",
            "Read an object's registry data (status, contacts, name servers, dates)",
            vec![
                object_param(),
                parameter(
                    "name",
                    "string",
                    "The domain or host name, or contact id",
                    true,
                ),
                parameter(
                    "auth_info",
                    "string",
                    "The object's authInfo password, to read another registrar's object",
                    false,
                ),
            ],
            json!({"type": "epp_info", "object": "domain", "name": "example.com"}),
        ),
        action(
            "epp_create_domain",
            "Register a domain",
            vec![
                parameter(
                    "name",
                    "string",
                    "The domain name to register, e.g. example.com",
                    true,
                ),
                parameter(
                    "period",
                    "number",
                    "Registration length in years, 1 to 10",
                    false,
                ),
                parameter("registrant", "string", "Registrant contact id", true),
                parameter(
                    "contacts",
                    "array",
                    "[{type: admin|tech|billing, id}]",
                    false,
                ),
                parameter("ns", "array", "Name server host names", false),
                parameter(
                    "auth_info",
                    "string",
                    "The domain's transfer password",
                    true,
                ),
            ],
            json!({"type": "epp_create_domain", "name": "example.com", "period": 1, "registrant": "jd1234", "contacts": [{"type": "admin", "id": "sh8013"}], "ns": ["ns1.example.net"], "auth_info": "2fooBAR"}),
        ),
        action(
            "epp_create_host",
            "Create a host (name server)",
            vec![
                parameter(
                    "name",
                    "string",
                    "The host (name server) name, e.g. ns1.example.com",
                    true,
                ),
                parameter(
                    "addrs",
                    "array",
                    "[{ip: v4|v6, addr}] for hosts inside the registry's zones",
                    false,
                ),
            ],
            json!({"type": "epp_create_host", "name": "ns1.example.com", "addrs": [{"ip": "v4", "addr": "192.0.2.2"}]}),
        ),
        action(
            "epp_create_contact",
            "Create a contact",
            vec![
                parameter(
                    "id",
                    "string",
                    "The new contact's id, 3 to 16 characters, e.g. sh8013",
                    true,
                ),
                parameter(
                    "name",
                    "string",
                    "The contact's full name, e.g. John Doe",
                    true,
                ),
                parameter(
                    "org",
                    "string",
                    "The contact's organisation, e.g. Example Inc.",
                    false,
                ),
                parameter("street", "array", "Up to three street lines", false),
                parameter(
                    "city",
                    "string",
                    "The postal address city, e.g. Dulles",
                    true,
                ),
                parameter("sp", "string", "State or province", false),
                parameter("pc", "string", "The postal code, e.g. 20166-6503", false),
                parameter("cc", "string", "Two-letter country code", true),
                parameter("voice", "string", "Phone, e.g. +1.7035555555", false),
                parameter(
                    "email",
                    "string",
                    "The contact's email address, e.g. jdoe@example.com",
                    true,
                ),
                parameter("auth_info", "string", "The contact's password", true),
            ],
            json!({"type": "epp_create_contact", "id": "sh8013", "name": "John Doe", "street": ["123 Example Dr."], "city": "Dulles", "cc": "US", "email": "jdoe@example.com", "auth_info": "2fooBAR"}),
        ),
        action(
            "epp_renew",
            "Extend a domain's registration from its current expiry",
            vec![
                parameter(
                    "name",
                    "string",
                    "The domain name to renew, e.g. example.com",
                    true,
                ),
                parameter(
                    "cur_exp_date",
                    "string",
                    "Its current expiry date, YYYY-MM-DD",
                    true,
                ),
                parameter(
                    "period",
                    "number",
                    "Years to add to the registration, 1 to 10",
                    false,
                ),
            ],
            json!({"type": "epp_renew", "name": "example.com", "cur_exp_date": "2027-04-03", "period": 1}),
        ),
        action(
            "epp_transfer",
            "Request, query, approve, reject or cancel a domain transfer",
            vec![
                parameter(
                    "op",
                    "string",
                    "request, query, approve, reject or cancel",
                    true,
                ),
                parameter(
                    "name",
                    "string",
                    "The domain name being transferred, e.g. example.com",
                    true,
                ),
                parameter(
                    "auth_info",
                    "string",
                    "The domain's transfer password (for request)",
                    false,
                ),
                parameter("period", "number", "Years added by the transfer", false),
            ],
            json!({"type": "epp_transfer", "op": "request", "name": "example.com", "auth_info": "2fooBAR"}),
        ),
        action(
            "epp_delete",
            "Delete an object",
            vec![
                object_param(),
                parameter(
                    "name",
                    "string",
                    "The domain or host name, or contact id",
                    true,
                ),
            ],
            json!({"type": "epp_delete", "object": "host", "name": "ns1.example.com"}),
        ),
        action(
            "epp_hello",
            "Ask the server for a fresh greeting (keeps the session alive)",
            vec![],
            json!({"type": "epp_hello"}),
        ),
        action(
            "epp_logout",
            "Log out and close the session",
            vec![],
            json!({"type": "epp_logout"}),
        ),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "epp_connected",
        "The server's greeting arrived (and the configured login, if any, was answered)",
        json!({"type": "epp_check", "object": "domain", "names": ["example.com"]}),
    )
    .with_parameters(vec![
        parameter("sv_id", "string", "The server's name", true),
        parameter("obj_uris", "array", "The object mappings it serves", true),
        parameter("ext_uris", "array", "The extensions it serves", true),
        parameter(
            "login",
            "object",
            "{code, message, reason} of the configured login, or null",
            false,
        ),
    ])
    .with_actions(defs())
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("epp_response", "The server answered a command", json!({"type": "epp_info", "object": "domain", "name": "example.com"}))
        .with_parameters(vec![
            parameter("command", "string", "The command answered, e.g. check", true),
            parameter("object", "string", "domain, host or contact, when the command had one", false),
            parameter("code", "number", "RFC 5730 result code: 1xxx success, 2xxx failure", true),
            parameter("message", "string", "The result message", true),
            parameter("reason", "string", "The server's explanation of a failure", false),
            parameter("data", "object", "The resData: results[] for a check, the object's fields for info, crDate/exDate for create, trStatus and dates for transfer", false),
            parameter("cl_trid", "string", "The client transaction id", false),
            parameter("sv_trid", "string", "The server transaction id", false),
        ])
        .with_actions(defs())
});

fn ns_of(object: &str) -> Result<(&'static str, &'static str)> {
    Ok(match object {
        "domain" => ("domain", DOMAIN),
        "host" => ("host", HOST),
        "contact" => ("contact", CONTACT),
        other => bail!("object is domain, host or contact, not {other}"),
    })
}

fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .filter(|s| !s.is_empty() && s.len() <= 255)
        .with_context(|| format!("{k} is required"))
}

fn opt(tag: &str, v: &Value, k: &str) -> String {
    v[k].as_str()
        .filter(|s| !s.is_empty())
        .map(|s| el(tag, s))
        .unwrap_or_default()
}

fn period(v: &Value, p: &str) -> Result<String> {
    Ok(match v["period"].as_u64() {
        None => String::new(),
        Some(n) => {
            ensure!((1..=99).contains(&n), "period is 1 to 99 years");
            format!(r#"<{p}:period unit="y">{n}</{p}:period>"#)
        }
    })
}

/// (command, object, the command element) for an action, or None for one that sends nothing.
pub fn render(v: &Value) -> Result<(String, Option<String>, String)> {
    let kind = v["type"].as_str().unwrap_or_default();
    let obj = |p: &str, ns: &str, verb: &str, body: String| {
        format!(r#"<{verb}><{p}:{verb} xmlns:{p}="{ns}">{body}</{p}:{verb}></{verb}>"#)
    };
    Ok(match kind {
        "epp_login" => (
            "login".into(),
            None,
            login(text(v, "client_id")?, text(v, "password")?),
        ),
        "epp_check" => {
            let object = text(v, "object")?;
            let (p, ns) = ns_of(object)?;
            let key = if object == "contact" { "id" } else { "name" };
            let names = v["names"].as_array().context("names is an array")?;
            ensure!((1..=64).contains(&names.len()), "1 to 64 names");
            let body: String = names
                .iter()
                .map(|n| {
                    n.as_str()
                        .filter(|s| !s.is_empty())
                        .map(|s| el(&format!("{p}:{key}"), s))
                        .context("names are strings")
                })
                .collect::<Result<_>>()?;
            (
                "check".into(),
                Some(object.into()),
                obj(p, ns, "check", body),
            )
        }
        "epp_info" | "epp_delete" => {
            let object = text(v, "object")?;
            let (p, ns) = ns_of(object)?;
            let key = if object == "contact" { "id" } else { "name" };
            let verb = if kind == "epp_info" { "info" } else { "delete" };
            let mut body = el(&format!("{p}:{key}"), text(v, "name")?);
            if verb == "info" {
                if let Some(pw) = v["auth_info"].as_str().filter(|s| !s.is_empty()) {
                    body.push_str(&format!(
                        "<{p}:authInfo>{}</{p}:authInfo>",
                        el(&format!("{p}:pw"), pw)
                    ));
                }
            }
            (verb.into(), Some(object.into()), obj(p, ns, verb, body))
        }
        "epp_create_domain" => {
            let mut body = el("domain:name", text(v, "name")?);
            body.push_str(&period(v, "domain")?);
            let ns: Vec<String> = v["ns"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|h| h.as_str().map(|h| el("domain:hostObj", h)))
                .collect();
            if !ns.is_empty() {
                body.push_str(&format!("<domain:ns>{}</domain:ns>", ns.concat()));
            }
            body.push_str(&el("domain:registrant", text(v, "registrant")?));
            for c in v["contacts"].as_array().into_iter().flatten() {
                let t = c["type"].as_str().unwrap_or("admin");
                ensure!(
                    matches!(t, "admin" | "tech" | "billing"),
                    "a contact type is admin, tech or billing"
                );
                body.push_str(&format!(
                    r#"<domain:contact type="{t}">{}</domain:contact>"#,
                    escape(c["id"].as_str().unwrap_or_default())
                ));
            }
            body.push_str(&format!(
                "<domain:authInfo>{}</domain:authInfo>",
                el("domain:pw", text(v, "auth_info")?)
            ));
            (
                "create".into(),
                Some("domain".into()),
                obj("domain", DOMAIN, "create", body),
            )
        }
        "epp_create_host" => {
            let mut body = el("host:name", text(v, "name")?);
            for a in v["addrs"].as_array().into_iter().flatten() {
                let ip = a["ip"].as_str().unwrap_or("v4");
                ensure!(matches!(ip, "v4" | "v6"), "ip is v4 or v6");
                let addr = a["addr"].as_str().context("each address has addr")?;
                ensure!(
                    addr.parse::<std::net::IpAddr>().is_ok(),
                    "{addr} is not an IP address"
                );
                body.push_str(&format!(
                    r#"<host:addr ip="{ip}">{}</host:addr>"#,
                    escape(addr)
                ));
            }
            (
                "create".into(),
                Some("host".into()),
                obj("host", HOST, "create", body),
            )
        }
        "epp_create_contact" => {
            let streets: String = v["street"]
                .as_array()
                .into_iter()
                .flatten()
                .take(3)
                .filter_map(|s| s.as_str().map(|s| el("contact:street", s)))
                .collect();
            let cc = text(v, "cc")?;
            ensure!(
                cc.len() == 2 && cc.bytes().all(|b| b.is_ascii_alphabetic()),
                "cc is a two-letter country code"
            );
            let body = format!(
                r#"{}<contact:postalInfo type="loc">{}{}<contact:addr>{streets}{}{}{}{}</contact:addr></contact:postalInfo>{}{}{}<contact:authInfo>{}</contact:authInfo>"#,
                el("contact:id", text(v, "id")?),
                el("contact:name", text(v, "name")?),
                opt("contact:org", v, "org"),
                el("contact:city", text(v, "city")?),
                opt("contact:sp", v, "sp"),
                opt("contact:pc", v, "pc"),
                el("contact:cc", cc),
                opt("contact:voice", v, "voice"),
                opt("contact:fax", v, "fax"),
                el("contact:email", text(v, "email")?),
                el("contact:pw", text(v, "auth_info")?),
            );
            (
                "create".into(),
                Some("contact".into()),
                obj("contact", CONTACT, "create", body),
            )
        }
        "epp_renew" => {
            let date = text(v, "cur_exp_date")?;
            ensure!(
                chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_ok(),
                "cur_exp_date is YYYY-MM-DD"
            );
            let body = format!(
                "{}{}{}",
                el("domain:name", text(v, "name")?),
                el("domain:curExpDate", date),
                period(v, "domain")?
            );
            (
                "renew".into(),
                Some("domain".into()),
                obj("domain", DOMAIN, "renew", body),
            )
        }
        "epp_transfer" => {
            let op = text(v, "op")?;
            ensure!(
                matches!(op, "request" | "query" | "approve" | "reject" | "cancel"),
                "op is request, query, approve, reject or cancel"
            );
            let mut body = el("domain:name", text(v, "name")?);
            body.push_str(&period(v, "domain")?);
            if let Some(pw) = v["auth_info"].as_str().filter(|s| !s.is_empty()) {
                body.push_str(&format!(
                    "<domain:authInfo>{}</domain:authInfo>",
                    el("domain:pw", pw)
                ));
            }
            (
                "transfer".into(),
                Some("domain".into()),
                format!(
                    r#"<transfer op="{op}"><domain:transfer xmlns:domain="{DOMAIN}">{body}</domain:transfer></transfer>"#
                ),
            )
        }
        "epp_logout" => ("logout".into(), None, "<logout/>".into()),
        "epp_hello" => ("hello".into(), None, String::new()),
        other => bail!("{other} is not an EPP client action"),
    })
}

pub fn login(client_id: &str, password: &str) -> String {
    format!(
        "<login>{}{}<options><version>1.0</version><lang>en</lang></options><svcs>{}{}{}</svcs></login>",
        el("clID", client_id),
        el("pw", password),
        el("objURI", DOMAIN),
        el("objURI", HOST),
        el("objURI", CONTACT)
    )
}

/// A whole command document.
pub fn document(command: &str, element: &str, cl_trid: &str) -> String {
    if command == "hello" {
        return format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?><epp xmlns="{EPP}"><hello/></epp>"#
        );
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?><epp xmlns="{EPP}"><command>{element}{}</command></epp>"#,
        el("clTRID", cl_trid)
    )
}

impl Protocol for EppClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "EPP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TLS>EPP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["epp", "epp client", "registrar", "domain registration"]
    }
    fn description(&self) -> &'static str {
        "EPP registrar client: logs in to a registry over TLS and checks, reads, creates, renews, transfers and deletes domains, hosts and contacts"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        defs()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        defs()
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
                "client_id",
                "string",
                "Log in as this registrar right after the greeting",
                json!("ClientX"),
                None,
            ),
            p(
                "password",
                "string",
                "The registrar's password",
                json!("foo-BAR2"),
                None,
            ),
            p(
                "tls",
                "boolean",
                "TLS as RFC 5734 requires; false for a plain-TCP server",
                json!(true),
                Some(json!(true)),
            ),
            p(
                "ca_cert_path",
                "string",
                "PEM certificate to trust instead of the public roots",
                json!("ca.pem"),
                None,
            ),
            p(
                "server_name",
                "string",
                "TLS name to verify; the remote host when omitted",
                json!("epp.example.net"),
                None,
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("tokio-rustls with RFC 5734 framing; commands rendered from structured actions and responses (greeting, result, resData, trID) parsed by the server's bounded XML reader")
            .llm_control("Every command after the greeting and the configured login")
            .e2e_testing("tests/client/epp: a registry built on the Swedish Internet Foundation's epp-lib v0.2.0 (independent Go EPP server library) answers checks, creates, infos, renews and transfers")
            .notes("No extensions or poll. Handler-driven commands chain to depth 16.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Log in to the EPP registry at epp.example.net:700 as ClientX and check whether example.com is available"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"epp","remote_addr":"127.0.0.1:7000","instruction":"Check whether example.com is available and register it if it is","startup_params":{"client_id":"ClientX","password":"foo-BAR2"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"epp_connected","handler":{"type":"static","actions":[{"type":"epp_check","object":"domain","names":["example.com"]}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"epp_connected","handler":{"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'epp_check','object':'domain','names':['example.com','example.net']}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for EppClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        render(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
