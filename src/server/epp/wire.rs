//! RFC 5734 framing, RFC 5730 commands as structured JSON, and the responses NetGet writes for
//! the domain (RFC 5731), host (RFC 5732) and contact (RFC 5733) mappings.
use super::xml::{el, escape, Node, CONTACT, DOMAIN, EPP, HOST};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The largest frame either side accepts, header included.
pub const MAX_FRAME: usize = 256 * 1024;

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let total = u32::from_be_bytes(len) as usize;
    ensure!(
        total > 4,
        "a frame length of {total} is shorter than its header"
    );
    ensure!(
        total <= MAX_FRAME,
        "a frame of {total} bytes exceeds {MAX_FRAME}"
    );
    let mut body = vec![0u8; total - 4];
    r.read_exact(&mut body).await?;
    Ok(Some(body))
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, xml: &str) -> Result<()> {
    ensure!(
        xml.len() + 4 <= MAX_FRAME,
        "a response of {} bytes exceeds {MAX_FRAME}",
        xml.len()
    );
    let mut out = Vec::with_capacity(xml.len() + 4);
    out.extend_from_slice(&((xml.len() + 4) as u32).to_be_bytes());
    out.extend_from_slice(xml.as_bytes());
    w.write_all(&out).await?;
    w.flush().await?;
    Ok(())
}

/// RFC 5730 §3 result codes with their standard messages.
pub const RESULT_CODES: &[(u16, &str)] = &[
    (1000, "Command completed successfully"),
    (1001, "Command completed successfully; action pending"),
    (1300, "Command completed successfully; no messages"),
    (1301, "Command completed successfully; ack to dequeue"),
    (1500, "Command completed successfully; ending session"),
    (2000, "Unknown command"),
    (2001, "Command syntax error"),
    (2002, "Command use error"),
    (2003, "Required parameter missing"),
    (2004, "Parameter value range error"),
    (2005, "Parameter value syntax error"),
    (2100, "Unimplemented protocol version"),
    (2101, "Unimplemented command"),
    (2102, "Unimplemented option"),
    (2103, "Unimplemented extension"),
    (2104, "Billing failure"),
    (2105, "Object is not eligible for renewal"),
    (2106, "Object is not eligible for transfer"),
    (2200, "Authentication error"),
    (2201, "Authorization error"),
    (2202, "Invalid authorization information"),
    (2300, "Object pending transfer"),
    (2301, "Object not pending transfer"),
    (2302, "Object exists"),
    (2303, "Object does not exist"),
    (2304, "Object status prohibits operation"),
    (2305, "Object association prohibits operation"),
    (2306, "Parameter value policy error"),
    (2307, "Unimplemented object service"),
    (2308, "Data management policy violation"),
    (2400, "Command failed"),
    (2500, "Command failed; server closing connection"),
    (2501, "Authentication error; server closing connection"),
    (2502, "Session limit exceeded; server closing connection"),
];

pub fn message(code: u16) -> &'static str {
    RESULT_CODES
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, m)| *m)
        .unwrap_or("Command failed")
}

/// A refusal decided while reading the command.
#[derive(Debug)]
pub struct Refusal {
    pub code: u16,
    pub reason: String,
}
fn refuse(code: u16, reason: impl Into<String>) -> Refusal {
    Refusal {
        code,
        reason: reason.into(),
    }
}

#[derive(Debug)]
pub enum Command {
    Hello,
    Login {
        client_id: String,
        password: String,
        version: String,
        obj_uris: Vec<String>,
    },
    Logout,
    Poll {
        op: String,
        msg_id: Option<String>,
    },
    /// An object command for the handler: (command, object, fields).
    Object(String, String, Value),
}

pub struct Frame {
    pub command: Command,
    pub cl_trid: Option<String>,
}

pub fn object_of(ns: &str) -> Option<&'static str> {
    match ns {
        DOMAIN => Some("domain"),
        HOST => Some("host"),
        CONTACT => Some("contact"),
        _ => None,
    }
}

pub fn namespace_of(object: &str) -> &'static str {
    match object {
        "domain" => DOMAIN,
        "host" => HOST,
        _ => CONTACT,
    }
}

fn required(n: &Node, name: &str) -> Result<String, Refusal> {
    n.text_of(name)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| refuse(2003, format!("{name} is required")))
}

fn auth_info(n: &Node) -> Option<String> {
    n.child("authInfo").and_then(|a| a.text_of("pw"))
}

fn period(n: &Node) -> Value {
    n.child("period")
        .map(|p| json!({"value": p.text().parse::<u32>().ok(), "unit": p.attr("unit").unwrap_or("y")}))
        .unwrap_or(Value::Null)
}

fn statuses(n: &Node) -> Vec<String> {
    n.all("status")
        .filter_map(|s| s.attr("s").map(str::to_owned))
        .collect()
}

fn domain_change(n: Option<&Node>) -> Value {
    let Some(n) = n else { return Value::Null };
    json!({
        "ns": n.child("ns").map(|ns| ns.texts_of("hostObj")).unwrap_or_default(),
        "contacts": n.all("contact").map(|c| json!({"type": c.attr("type").unwrap_or(""), "id": c.text()})).collect::<Vec<_>>(),
        "status": statuses(n),
    })
}

fn addresses(n: &Node) -> Vec<Value> {
    n.all("addr")
        .map(|a| json!({"ip": a.attr("ip").unwrap_or("v4"), "addr": a.text()}))
        .collect()
}

/// The fields of an object command, as the handler sees them.
fn fields(command: &str, object: &str, n: &Node) -> Result<Value, Refusal> {
    let key = if object == "contact" { "id" } else { "name" };
    Ok(match (command, object) {
        ("check", _) => {
            let names = n.texts_of(key);
            if names.is_empty() {
                return Err(refuse(2003, format!("check names at least one {key}")));
            }
            if names.len() > 64 {
                return Err(refuse(2306, "at most 64 objects per check"));
            }
            json!({"names": names})
        }
        ("info", _) => json!({key: required(n, key)?, "auth_info": auth_info(n)}),
        ("delete", _) => json!({key: required(n, key)?}),
        ("create", "domain") => json!({
            "name": required(n, "name")?,
            "period": period(n),
            "ns": n.child("ns").map(|ns| ns.texts_of("hostObj")).unwrap_or_default(),
            "registrant": n.text_of("registrant"),
            "contacts": n.all("contact").map(|c| json!({"type": c.attr("type").unwrap_or(""), "id": c.text()})).collect::<Vec<_>>(),
            "auth_info": auth_info(n),
        }),
        ("create", "host") => json!({"name": required(n, "name")?, "addrs": addresses(n)}),
        ("create", "contact") => {
            let postal = n.child("postalInfo");
            let addr = postal.and_then(|p| p.child("addr"));
            json!({
                "id": required(n, "id")?,
                "name": postal.and_then(|p| p.text_of("name")),
                "org": postal.and_then(|p| p.text_of("org")),
                "street": addr.map(|a| a.texts_of("street")).unwrap_or_default(),
                "city": addr.and_then(|a| a.text_of("city")),
                "sp": addr.and_then(|a| a.text_of("sp")),
                "pc": addr.and_then(|a| a.text_of("pc")),
                "cc": addr.and_then(|a| a.text_of("cc")),
                "voice": n.text_of("voice"),
                "fax": n.text_of("fax"),
                "email": n.text_of("email"),
                "auth_info": auth_info(n),
            })
        }
        ("renew", "domain") => json!({
            "name": required(n, "name")?,
            "cur_exp_date": required(n, "curExpDate")?,
            "period": period(n),
        }),
        ("transfer", "domain") | ("transfer", "contact") => {
            json!({key: required(n, key)?, "period": period(n), "auth_info": auth_info(n)})
        }
        ("update", "domain") => json!({
            "name": required(n, "name")?,
            "add": domain_change(n.child("add")),
            "rem": domain_change(n.child("rem")),
            "chg": n.child("chg").map(|c| json!({"registrant": c.text_of("registrant"), "auth_info": auth_info(c)})),
        }),
        ("update", "host") => json!({
            "name": required(n, "name")?,
            "add": n.child("add").map(|a| json!({"addrs": addresses(a), "status": statuses(a)})),
            "rem": n.child("rem").map(|a| json!({"addrs": addresses(a), "status": statuses(a)})),
            "new_name": n.child("chg").and_then(|c| c.text_of("name")),
        }),
        ("update", "contact") => {
            json!({"id": required(n, "id")?, "change": n.child("chg").map(|c| json!({"email": c.text_of("email"), "voice": c.text_of("voice")}))})
        }
        (c, o) => {
            return Err(refuse(
                2101,
                format!("{c} is not implemented for {o} objects"),
            ))
        }
    })
}

/// Read a frame's command.
pub fn command(root: &Node) -> Result<Frame, Refusal> {
    if root.ns != EPP || root.name != "epp" {
        return Err(refuse(
            2001,
            "the root element is not epp in urn:ietf:params:xml:ns:epp-1.0",
        ));
    }
    let inner = root
        .first()
        .ok_or_else(|| refuse(2001, "an empty epp element"))?;
    if inner.ns != EPP {
        return Err(refuse(2001, "an element outside the EPP namespace"));
    }
    match inner.name.as_str() {
        "hello" => {
            return Ok(Frame {
                command: Command::Hello,
                cl_trid: None,
            })
        }
        "command" => {}
        other => return Err(refuse(2001, format!("{other} is not a command"))),
    }
    let cl_trid = inner.text_of("clTRID").filter(|t| !t.is_empty());
    if cl_trid
        .as_ref()
        .is_some_and(|t| t.len() < 3 || t.len() > 64)
    {
        return Err(refuse(2005, "clTRID is 3 to 64 characters"));
    }
    let verb = inner
        .children
        .iter()
        .find(|c| c.name != "clTRID" && c.name != "extension")
        .ok_or_else(|| refuse(2001, "a command names no operation"))?;
    if verb.ns != EPP {
        return Err(refuse(2001, "the operation is not in the EPP namespace"));
    }
    let command = match verb.name.as_str() {
        "login" => Command::Login {
            client_id: required(verb, "clID")?,
            password: required(verb, "pw")?,
            version: verb
                .child("options")
                .and_then(|o| o.text_of("version"))
                .unwrap_or_default(),
            obj_uris: verb
                .child("svcs")
                .map(|s| s.texts_of("objURI"))
                .unwrap_or_default(),
        },
        "logout" => Command::Logout,
        "poll" => Command::Poll {
            op: verb.attr("op").unwrap_or("req").to_owned(),
            msg_id: verb.attr("msgID").map(str::to_owned),
        },
        name @ ("check" | "info" | "create" | "delete" | "renew" | "transfer" | "update") => {
            let obj = verb
                .first()
                .ok_or_else(|| refuse(2001, format!("{name} names no object")))?;
            let object = object_of(&obj.ns)
                .ok_or_else(|| refuse(2307, format!("{} objects are not served", obj.ns)))?;
            if obj.name != name {
                return Err(refuse(
                    2001,
                    format!("{name} holds {}:{}", object, obj.name),
                ));
            }
            let mut f = fields(name, object, obj)?;
            if name == "transfer" {
                let op = verb.attr("op").unwrap_or("");
                if !matches!(op, "request" | "query" | "approve" | "reject" | "cancel") {
                    return Err(refuse(
                        2005,
                        "transfer op is request, query, approve, reject or cancel",
                    ));
                }
                f["op"] = json!(op);
            }
            Command::Object(name.to_owned(), object.to_owned(), f)
        }
        other => return Err(refuse(2000, format!("{other} is not an EPP command"))),
    };
    Ok(Frame { command, cl_trid })
}

pub fn greeting(server_id: &str, now: &str, objects: &[&str]) -> String {
    let uris: String = objects
        .iter()
        .map(|o| el("objURI", namespace_of(o)))
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?><epp xmlns="{EPP}"><greeting>{}{}<svcMenu><version>1.0</version><lang>en</lang>{uris}</svcMenu><dcp><access><all/></access><statement><purpose><admin/><prov/></purpose><recipient><ours/><public/></recipient><retention><stated/></retention></statement></dcp></greeting></epp>"#,
        el("svID", server_id),
        el("svDate", now)
    )
}

pub fn response(
    code: u16,
    msg: &str,
    reason: Option<&str>,
    res_data: &str,
    cl_trid: Option<&str>,
    sv_trid: &str,
) -> String {
    let reason = reason
        .filter(|r| !r.is_empty())
        .map(|r| {
            format!(
                "<extValue><value><text/></value>{}</extValue>",
                el("reason", r)
            )
        })
        .unwrap_or_default();
    let res_data = if res_data.is_empty() {
        String::new()
    } else {
        format!("<resData>{res_data}</resData>")
    };
    let cl = cl_trid.map(|c| el("clTRID", c)).unwrap_or_default();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?><epp xmlns="{EPP}"><response><result code="{code}">{}{reason}</result>{res_data}<trID>{cl}{}</trID></response></epp>"#,
        el("msg", msg),
        el("svTRID", sv_trid)
    )
}

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str).filter(|x| !x.is_empty())
}
fn opt(tag: &str, v: &Value, k: &str) -> String {
    s(v, k).map(|x| el(tag, x)).unwrap_or_default()
}
fn list(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The resData a handler action describes, for the command it answers.
pub fn res_data(action: &Value, command: &str, object: &str) -> Result<String> {
    let p = object;
    let ns = namespace_of(object);
    let key = if object == "contact" { "id" } else { "name" };
    let status = |v: &Value| -> String {
        let st = list(v, "status");
        let st = if st.is_empty() {
            vec!["ok".to_owned()]
        } else {
            st
        };
        st.iter()
            .map(|x| format!(r#"<{p}:status s="{}"/>"#, escape(x)))
            .collect()
    };
    Ok(match action["type"].as_str().unwrap_or_default() {
        "epp_check_result" => {
            ensure!(command == "check", "epp_check_result answers check");
            let mut cds = String::new();
            for r in action["results"]
                .as_array()
                .context("results is an array")?
            {
                let name = s(r, "name").context("each result names its object")?;
                let avail = r["available"]
                    .as_bool()
                    .context("each result says available")?;
                let reason = if avail {
                    String::new()
                } else {
                    format!(
                        "<{p}:reason>{}</{p}:reason>",
                        escape(s(r, "reason").unwrap_or("In use"))
                    )
                };
                cds.push_str(&format!(
                    r#"<{p}:cd><{p}:{key} avail="{}">{}</{p}:{key}>{reason}</{p}:cd>"#,
                    if avail { 1 } else { 0 },
                    escape(name)
                ));
            }
            format!(r#"<{p}:chkData xmlns:{p}="{ns}">{cds}</{p}:chkData>"#)
        }
        "epp_info" => {
            ensure!(command == "info", "epp_info answers info");
            let o = &action["info"];
            let id = s(o, key).context("the object names itself")?;
            let mut body = format!("<{p}:{key}>{}</{p}:{key}>", escape(id));
            body.push_str(&format!(
                "<{p}:roid>{}</{p}:roid>",
                escape(s(o, "roid").unwrap_or("1-NETGET"))
            ));
            body.push_str(&status(o));
            match object {
                "domain" => {
                    body.push_str(&opt(&format!("{p}:registrant"), o, "registrant"));
                    for c in o["contacts"].as_array().into_iter().flatten() {
                        body.push_str(&format!(
                            r#"<{p}:contact type="{}">{}</{p}:contact>"#,
                            escape(s(c, "type").unwrap_or("admin")),
                            escape(s(c, "id").unwrap_or_default())
                        ));
                    }
                    let ns_list = list(o, "ns");
                    if !ns_list.is_empty() {
                        body.push_str(&format!(
                            "<{p}:ns>{}</{p}:ns>",
                            ns_list
                                .iter()
                                .map(|h| el(&format!("{p}:hostObj"), h))
                                .collect::<String>()
                        ));
                    }
                }
                "host" => {
                    for a in o["addrs"].as_array().into_iter().flatten() {
                        body.push_str(&format!(
                            r#"<{p}:addr ip="{}">{}</{p}:addr>"#,
                            escape(s(a, "ip").unwrap_or("v4")),
                            escape(s(a, "addr").unwrap_or_default())
                        ));
                    }
                }
                _ => {
                    let streets: String = list(o, "street")
                        .iter()
                        .map(|x| el(&format!("{p}:street"), x))
                        .collect();
                    body.push_str(&format!(
                        r#"<{p}:postalInfo type="loc">{}{}<{p}:addr>{streets}{}{}{}{}</{p}:addr></{p}:postalInfo>{}{}"#,
                        opt(&format!("{p}:name"), o, "name"),
                        opt(&format!("{p}:org"), o, "org"),
                        opt(&format!("{p}:city"), o, "city"),
                        opt(&format!("{p}:sp"), o, "sp"),
                        opt(&format!("{p}:pc"), o, "pc"),
                        opt(&format!("{p}:cc"), o, "cc"),
                        opt(&format!("{p}:voice"), o, "voice"),
                        opt(&format!("{p}:email"), o, "email"),
                    ));
                }
            }
            body.push_str(&format!(
                "<{p}:clID>{}</{p}:clID>",
                escape(s(o, "cl_id").unwrap_or("netget"))
            ));
            body.push_str(&opt(&format!("{p}:crID"), o, "cr_id"));
            body.push_str(&opt(&format!("{p}:crDate"), o, "cr_date"));
            body.push_str(&opt(&format!("{p}:upDate"), o, "up_date"));
            if object == "domain" {
                body.push_str(&opt(&format!("{p}:exDate"), o, "ex_date"));
            }
            if let Some(pw) = s(o, "auth_info") {
                body.push_str(&format!(
                    "<{p}:authInfo>{}</{p}:authInfo>",
                    el(&format!("{p}:pw"), pw)
                ));
            }
            format!(r#"<{p}:infData xmlns:{p}="{ns}">{body}</{p}:infData>"#)
        }
        "epp_created" => {
            ensure!(command == "create", "epp_created answers create");
            let id = s(action, key).context("epp_created names the object")?;
            format!(
                r#"<{p}:creData xmlns:{p}="{ns}"><{p}:{key}>{}</{p}:{key}>{}{}</{p}:creData>"#,
                escape(id),
                opt(&format!("{p}:crDate"), action, "cr_date"),
                if object == "domain" {
                    opt(&format!("{p}:exDate"), action, "ex_date")
                } else {
                    String::new()
                }
            )
        }
        "epp_renewed" => {
            ensure!(command == "renew", "epp_renewed answers renew");
            format!(
                r#"<{p}:renData xmlns:{p}="{ns}"><{p}:name>{}</{p}:name>{}</{p}:renData>"#,
                escape(s(action, "name").context("epp_renewed names the domain")?),
                opt(&format!("{p}:exDate"), action, "ex_date")
            )
        }
        "epp_transfer_status" => {
            ensure!(
                command == "transfer",
                "epp_transfer_status answers transfer"
            );
            format!(
                r#"<{p}:trnData xmlns:{p}="{ns}"><{p}:{key}>{}</{p}:{key}>{}{}{}{}{}{}</{p}:trnData>"#,
                escape(s(action, key).context("epp_transfer_status names the object")?),
                opt(&format!("{p}:trStatus"), action, "tr_status"),
                opt(&format!("{p}:reID"), action, "re_id"),
                opt(&format!("{p}:reDate"), action, "re_date"),
                opt(&format!("{p}:acID"), action, "ac_id"),
                opt(&format!("{p}:acDate"), action, "ac_date"),
                if object == "domain" {
                    opt(&format!("{p}:exDate"), action, "ex_date")
                } else {
                    String::new()
                }
            )
        }
        "epp_result" => String::new(),
        other => bail!("{other} is not an EPP answer"),
    })
}

/// A response frame read back by a client: code, message, reason, transaction ids and the
/// resData flattened per object.
pub fn read_response(root: &Node) -> Result<Value> {
    ensure!(root.ns == EPP && root.name == "epp", "not an EPP document");
    let inner = root.first().context("an empty epp element")?;
    if inner.name == "greeting" {
        let menu = inner.child("svcMenu");
        return Ok(json!({
            "greeting": true,
            "sv_id": inner.text_of("svID"),
            "sv_date": inner.text_of("svDate"),
            "versions": menu.map(|m| m.texts_of("version")).unwrap_or_default(),
            "langs": menu.map(|m| m.texts_of("lang")).unwrap_or_default(),
            "obj_uris": menu.map(|m| m.texts_of("objURI")).unwrap_or_default(),
            "ext_uris": menu.and_then(|m| m.child("svcExtension")).map(|e| e.texts_of("extURI")).unwrap_or_default(),
        }));
    }
    ensure!(
        inner.name == "response",
        "neither a greeting nor a response"
    );
    let result = inner
        .child("result")
        .context("a response without a result")?;
    let code: u16 = result
        .attr("code")
        .and_then(|c| c.parse().ok())
        .context("a result without a code")?;
    let reason = result
        .child("extValue")
        .and_then(|x| x.text_of("reason"))
        .or_else(|| result.text_of("reason"));
    let tr = inner.child("trID");
    let mut data = Map::new();
    if let Some(rd) = inner.child("resData").and_then(Node::first) {
        data.insert("kind".into(), json!(rd.name));
        data.insert("object".into(), json!(object_of(&rd.ns)));
        match rd.name.as_str() {
            "chkData" => {
                let results: Vec<Value> = rd
                    .all("cd")
                    .map(|cd| {
                        let n = cd.child("name").or_else(|| cd.child("id"));
                        json!({
                            "name": n.map(Node::text),
                            "available": n.and_then(|n| n.attr("avail")).is_some_and(|a| a == "1" || a == "true"),
                            "reason": cd.text_of("reason"),
                        })
                    })
                    .collect();
                data.insert("results".into(), json!(results));
            }
            _ => {
                for c in &rd.children {
                    let value = match c.name.as_str() {
                        "status" => json!(c.attr("s")),
                        "contact" => json!({"type": c.attr("type"), "id": c.text()}),
                        "addr" if c.children.is_empty() => {
                            json!({"ip": c.attr("ip"), "addr": c.text()})
                        }
                        "ns" => json!(c.texts_of("hostObj")),
                        "authInfo" => json!(c.text_of("pw")),
                        "postalInfo" => {
                            let addr = c.child("addr");
                            json!({"name": c.text_of("name"), "org": c.text_of("org"), "street": addr.map(|a| a.texts_of("street")), "city": addr.and_then(|a| a.text_of("city")), "cc": addr.and_then(|a| a.text_of("cc"))})
                        }
                        _ => json!(c.text()),
                    };
                    match c.name.as_str() {
                        "status" | "contact" | "addr" => {
                            let key = if c.name == "status" {
                                "status"
                            } else if c.name == "contact" {
                                "contacts"
                            } else {
                                "addrs"
                            };
                            data.entry(key.to_owned())
                                .or_insert_with(|| json!([]))
                                .as_array_mut()
                                .map(|a| a.push(value));
                        }
                        name => {
                            data.insert(name.to_owned(), value);
                        }
                    }
                }
            }
        }
    }
    Ok(json!({
        "code": code,
        "message": result.text_of("msg"),
        "reason": reason,
        "cl_trid": tr.and_then(|t| t.text_of("clTRID")),
        "sv_trid": tr.and_then(|t| t.text_of("svTRID")),
        "data": data,
    }))
}
