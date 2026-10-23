//! ONVIF on the wire, for both roles: SOAP 1.2 envelopes read into a bounded,
//! namespace-resolved element tree; WS-Security UsernameToken password digests; and the
//! envelopes NetGet writes, with every value XML-escaped. Nothing the model says is spliced into
//! an envelope raw.
use anyhow::{bail, ensure, Context, Result};
use base64::Engine;
use quick_xml::escape::escape;
use quick_xml::events::Event as XmlEvent;
use quick_xml::name::ResolveResult;
use quick_xml::NsReader;
use serde_json::{json, Map, Value};
use sha1::{Digest, Sha1};

/// A request envelope at most (the device side). ONVIF requests are a few kilobytes.
pub const MAX_REQUEST: usize = 256 * 1024;
/// A response envelope at most (the client side): a device with many profiles answers in
/// tens of kilobytes.
pub const MAX_RESPONSE: usize = 1024 * 1024;
/// Element nesting at most, in either direction.
pub const MAX_DEPTH: usize = 32;
/// Elements in one envelope at most.
pub const MAX_ELEMENTS: usize = 20_000;
/// Items (profiles, scopes, interfaces, sources, services) one answer may carry.
pub const MAX_ITEMS: usize = 64;
/// A decoded WS-Security nonce at most.
pub const MAX_NONCE: usize = 128;

pub const ENV: &str = "http://www.w3.org/2003/05/soap-envelope";
pub const ENV11: &str = "http://schemas.xmlsoap.org/soap/envelope/";
pub const TDS: &str = "http://www.onvif.org/ver10/device/wsdl";
pub const TRT: &str = "http://www.onvif.org/ver10/media/wsdl";
pub const TT: &str = "http://www.onvif.org/ver10/schema";
pub const TER: &str = "http://www.onvif.org/ver10/error";
pub const TPTZ: &str = "http://www.onvif.org/ver20/ptz/wsdl";
pub const TEV: &str = "http://www.onvif.org/ver10/events/wsdl";
pub const TR2: &str = "http://www.onvif.org/ver20/media/wsdl";
pub const TIMG: &str = "http://www.onvif.org/ver20/imaging/wsdl";
pub const WSNT: &str = "http://docs.oasis-open.org/wsn/b-2";
pub const WSA: &str = "http://www.w3.org/2005/08/addressing";
pub const WSTOP: &str = "http://docs.oasis-open.org/wsn/t-1";
pub const TNS1: &str = "http://www.onvif.org/ver10/topics";
pub const XS: &str = "http://www.w3.org/2001/XMLSchema";
pub const WSSE: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
pub const WSU: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
pub const PASSWORD_DIGEST: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";
pub const BASE64_BINARY: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";

/// Where the services live on a NetGet device, and where a client looks first. Requests are
/// dispatched on the Body element's namespace, so these paths are what is advertised, not what
/// is required — except a pull-point subscription's, whose path names the subscription.
pub const DEVICE_PATH: &str = "/onvif/device_service";
pub const MEDIA_PATH: &str = "/onvif/media_service";
pub const MEDIA2_PATH: &str = "/onvif/media2_service";
pub const PTZ_PATH: &str = "/onvif/ptz_service";
pub const EVENTS_PATH: &str = "/onvif/events_service";
pub const IMAGING_PATH: &str = "/onvif/imaging_service";
/// A pull-point subscription's address is this prefix and the subscription's id.
pub const SUBSCRIPTION_PREFIX: &str = "/onvif/events/subscription/";
/// The longest xsd:duration accepted anywhere (a subscription lifetime, a PTZ timeout).
pub const MAX_DURATION: std::time::Duration = std::time::Duration::from_secs(86_400);
/// An xsd:duration or xsd:dateTime string at most.
pub const MAX_TIME_TEXT: usize = 64;

#[derive(Debug, Default, Clone)]
pub struct Element {
    /// The resolved namespace URI ("" when unqualified).
    pub ns: String,
    pub name: String,
    /// Attributes by local name.
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Element>,
    pub text: String,
}

impl Element {
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.children.iter().filter(move |c| c.name == name)
    }
    pub fn text_of(&self, name: &str) -> Option<String> {
        self.child(name).map(|c| c.text.trim().to_string())
    }
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
    /// The text at a path of child names.
    pub fn path(&self, names: &[&str]) -> Option<String> {
        let mut e = self;
        for n in names {
            e = e.child(n)?;
        }
        Some(e.text.trim().to_string())
    }
}

fn local(name: &[u8]) -> String {
    let s = String::from_utf8_lossy(name);
    s.rsplit(':').next().unwrap_or_default().to_string()
}

/// The element tree of an XML document, bounded in size, depth and element count, with every
/// element's namespace resolved. A DOCTYPE is refused, so there is no entity expansion.
pub fn tree(xml: &[u8], max: usize) -> Result<Element> {
    ensure!(xml.len() <= max, "document larger than {max} bytes");
    let mut reader = NsReader::from_reader(xml);
    reader.config_mut().trim_text(false);
    let mut stack: Vec<Element> = vec![Element::default()];
    let mut count = 0usize;
    let mut buf = Vec::new();
    loop {
        let (ns, ev) = reader
            .read_resolved_event_into(&mut buf)
            .context("the document is not well-formed XML")?;
        let ns = match ns {
            ResolveResult::Bound(n) => String::from_utf8_lossy(n.as_ref()).into_owned(),
            ResolveResult::Unbound => String::new(),
            ResolveResult::Unknown(p) => {
                bail!(
                    "undeclared namespace prefix {}",
                    String::from_utf8_lossy(&p)
                )
            }
        };
        let empty = matches!(ev, XmlEvent::Empty(_));
        match ev {
            XmlEvent::Start(e) | XmlEvent::Empty(e) => {
                count += 1;
                ensure!(count <= MAX_ELEMENTS, "more than {MAX_ELEMENTS} elements");
                ensure!(stack.len() <= MAX_DEPTH, "nested deeper than {MAX_DEPTH}");
                let mut el = Element {
                    ns,
                    name: local(e.local_name().as_ref()),
                    ..Default::default()
                };
                for a in e.attributes() {
                    let a = a.context("a malformed attribute")?;
                    let v = a
                        .decode_and_unescape_value(reader.decoder())
                        .context("a malformed attribute value")?
                        .into_owned();
                    el.attrs.push((local(a.key.local_name().as_ref()), v));
                }
                if empty {
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(el);
                    }
                } else {
                    stack.push(el);
                }
            }
            XmlEvent::End(_) => {
                ensure!(stack.len() > 1, "an end tag with nothing open");
                let el = stack.pop().unwrap_or_default();
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(el);
                }
            }
            XmlEvent::Text(t) => {
                if let Some(top) = stack.last_mut() {
                    top.text
                        .push_str(&t.unescape().context("a bad character reference")?);
                }
            }
            XmlEvent::CData(t) => {
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&String::from_utf8_lossy(&t));
                }
            }
            XmlEvent::DocType(_) => bail!("a DOCTYPE is not allowed in a SOAP envelope"),
            XmlEvent::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    ensure!(stack.len() == 1, "the document ends inside an element");
    stack
        .pop()
        .unwrap_or_default()
        .children
        .into_iter()
        .next()
        .context("an empty document")
}

/// A WS-Security UsernameToken as it arrived.
#[derive(Debug, Default, Clone)]
pub struct UsernameToken {
    pub username: String,
    pub password: String,
    pub password_type: Option<String>,
    pub nonce: Option<String>,
    pub nonce_encoding: Option<String>,
    pub created: Option<String>,
}

/// One SOAP request: its envelope version, its UsernameToken (if any) and the operation
/// element in the Body.
#[derive(Debug)]
pub struct Request {
    /// The envelope's namespace was SOAP 1.2's.
    pub soap12: bool,
    pub token: Option<UsernameToken>,
    /// The operation's namespace (`TDS`, `TRT`, or anything else) and local name.
    pub ns: String,
    pub operation: String,
    pub body: Element,
    /// The WS-Addressing To header, when the client sent one.
    pub to: Option<String>,
}

pub fn parse_request(xml: &[u8]) -> Result<Request> {
    let env = tree(xml, MAX_REQUEST)?;
    ensure!(
        env.name == "Envelope" && (env.ns == ENV || env.ns == ENV11),
        "not a SOAP envelope"
    );
    let token = env
        .child("Header")
        .and_then(|h| {
            h.children
                .iter()
                .find(|c| c.name == "Security" && c.ns == WSSE)
        })
        .and_then(|s| s.child("UsernameToken"))
        .map(|t| UsernameToken {
            username: t.text_of("Username").unwrap_or_default(),
            password: t.text_of("Password").unwrap_or_default(),
            password_type: t
                .child("Password")
                .and_then(|p| p.attr("Type"))
                .map(str::to_string),
            nonce: t.text_of("Nonce"),
            nonce_encoding: t
                .child("Nonce")
                .and_then(|n| n.attr("EncodingType"))
                .map(str::to_string),
            created: t.text_of("Created"),
        });
    let to = env
        .child("Header")
        .and_then(|h| h.children.iter().find(|c| c.name == "To" && c.ns == WSA))
        .map(|t| t.text.trim().to_string());
    let body = env.child("Body").context("the envelope has no Body")?;
    let op = body.children.first().context("the Body is empty")?.clone();
    Ok(Request {
        soap12: env.ns == ENV,
        token,
        ns: op.ns.clone(),
        operation: op.name.clone(),
        body: op,
        to,
    })
}

/// `Base64(SHA-1(nonce ‖ created ‖ password))`, the UsernameToken Profile 1.0 digest ONVIF
/// requires.
pub fn password_digest(nonce: &[u8], created: &str, password: &str) -> String {
    let mut h = Sha1::new();
    h.update(nonce);
    h.update(created.as_bytes());
    h.update(password.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Why a UsernameToken was refused, for the log (the peer only ever hears NotAuthorized).
pub type Refusal = &'static str;

/// Check a UsernameToken against the configured credentials: a PasswordDigest whose nonce is
/// base64, whose Created is within `max_skew` of `now`, for the configured user. Returns the
/// decoded nonce, which the caller remembers so it cannot be replayed.
pub fn verify_token(
    token: Option<&UsernameToken>,
    username: &str,
    password: &str,
    now: chrono::DateTime<chrono::Utc>,
    max_skew: chrono::Duration,
) -> std::result::Result<Vec<u8>, Refusal> {
    let t = token.ok_or("no_username_token")?;
    match t.password_type.as_deref() {
        Some(PASSWORD_DIGEST) => {}
        Some(other) if other.ends_with("#PasswordDigest") => {}
        _ => return Err("password_not_digest"),
    }
    // The token profile's default nonce encoding is Base64Binary; anything else is refused.
    if !t
        .nonce_encoding
        .as_deref()
        .is_none_or(|e| e.ends_with("#Base64Binary"))
    {
        return Err("nonce_not_base64");
    }
    let nonce = base64::engine::general_purpose::STANDARD
        .decode(t.nonce.as_deref().ok_or("no_nonce")?.trim())
        .map_err(|_| "nonce_not_base64")?;
    if nonce.is_empty() || nonce.len() > MAX_NONCE {
        return Err("bad_nonce_length");
    }
    let created = t.created.as_deref().ok_or("no_created")?;
    if created.len() > 64 {
        return Err("bad_created");
    }
    let when = chrono::DateTime::parse_from_rfc3339(created)
        .map_err(|_| "bad_created")?
        .with_timezone(&chrono::Utc);
    if (now - when).abs() > max_skew {
        return Err("stale_created");
    }
    let expected = password_digest(&nonce, created, password);
    let user_ok = constant_time_eq(t.username.as_bytes(), username.as_bytes());
    let digest_ok = constant_time_eq(t.password.trim().as_bytes(), expected.as_bytes());
    if !user_ok {
        return Err("unknown_user");
    }
    if !digest_ok {
        return Err("bad_digest");
    }
    Ok(nonce)
}

pub fn esc(s: &str) -> String {
    escape(s).into_owned()
}

/// A SOAP 1.2 response envelope around a Body's content.
pub fn envelope(body: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<env:Envelope {}><env:Body>{body}</env:Body></env:Envelope>",
        namespaces()
    )
}

/// Every prefix NetGet writes, declared once on the Envelope: a notification's topic is a QName
/// in element text (`tns1:VideoSource/MotionAlarm`), so its prefix must be in scope there.
pub fn namespaces() -> String {
    [
        ("env", ENV),
        ("tds", TDS),
        ("trt", TRT),
        ("tr2", TR2),
        ("tptz", TPTZ),
        ("tev", TEV),
        ("timg", TIMG),
        ("tt", TT),
        ("ter", TER),
        ("wsnt", WSNT),
        ("wsa", WSA),
        ("wstop", WSTOP),
        ("tns1", TNS1),
        ("xs", XS),
    ]
    .iter()
    .map(|(p, ns)| format!("xmlns:{p}=\"{ns}\""))
    .collect::<Vec<_>>()
    .join(" ")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultCode {
    Sender,
    Receiver,
    VersionMismatch,
}

impl FaultCode {
    pub fn name(self) -> &'static str {
        match self {
            FaultCode::Sender => "Sender",
            FaultCode::Receiver => "Receiver",
            FaultCode::VersionMismatch => "VersionMismatch",
        }
    }
}

/// A SOAP 1.2 Fault: `env:<code>`, then each `ter:<subcode>` nested inside the last.
pub fn fault(code: FaultCode, subcodes: &[&str], reason: &str) -> String {
    fault_with_detail(code, subcodes, reason, "")
}

/// A Fault carrying a Detail element; `detail` is XML NetGet wrote itself, such as a
/// WS-BaseNotification fault type (`<wsnt:UnacceptableInitialTerminationTimeFault/>`).
pub fn fault_with_detail(code: FaultCode, subcodes: &[&str], reason: &str, detail: &str) -> String {
    let mut sub = String::new();
    for s in subcodes.iter().rev() {
        sub = format!(
            "<env:Subcode><env:Value>ter:{}</env:Value>{sub}</env:Subcode>",
            esc(s)
        );
    }
    let detail = if detail.is_empty() {
        String::new()
    } else {
        format!("<env:Detail>{detail}</env:Detail>")
    };
    format!(
        "<env:Fault><env:Code><env:Value>env:{}</env:Value>{sub}</env:Code><env:Reason><env:Text xml:lang=\"en\">{}</env:Text></env:Reason>{detail}</env:Fault>",
        code.name(),
        esc(reason)
    )
}

/// An xsd:duration (`PnYnMnDTnHnMnS`, fractional seconds allowed) as a std Duration. Years and
/// months are refused (their length is not fixed); negative durations are refused; anything past
/// `MAX_DURATION` is refused. No recursion and no unbounded arithmetic: every component is
/// checked against the bound before it is added.
pub fn parse_duration(text: &str) -> Result<std::time::Duration> {
    let t = text.trim();
    ensure!(
        !t.is_empty() && t.len() <= MAX_TIME_TEXT,
        "a duration is 1-{MAX_TIME_TEXT} characters"
    );
    let rest = t.strip_prefix('P').context("a duration starts with P")?;
    ensure!(!rest.is_empty(), "a duration has at least one component");
    let mut secs = 0f64;
    let mut in_time = false;
    let mut number = String::new();
    let mut components = 0;
    let mut last_unit = 0u8;
    for c in rest.chars() {
        match c {
            'T' => {
                ensure!(!in_time && number.is_empty(), "a misplaced T in a duration");
                in_time = true;
                last_unit = 0;
            }
            '0'..='9' | '.' => {
                ensure!(number.len() < 20, "a duration component is too long");
                number.push(c);
            }
            _ => {
                ensure!(!number.is_empty(), "a duration unit without a number");
                let (rank, scale) = match (in_time, c) {
                    (false, 'D') => (1, 86_400.0),
                    (true, 'H') => (2, 3_600.0),
                    (true, 'M') => (3, 60.0),
                    (true, 'S') => (4, 1.0),
                    (false, 'Y' | 'M') => bail!("durations in years or months are not supported"),
                    _ => bail!("an unknown duration unit {c:?}"),
                };
                ensure!(rank > last_unit, "duration units out of order");
                last_unit = rank;
                ensure!(
                    c == 'S' || !number.contains('.'),
                    "only seconds may be fractional"
                );
                let n: f64 = number.parse().context("a duration number")?;
                ensure!(n.is_finite(), "a duration number is not finite");
                secs += n * scale;
                ensure!(
                    secs <= MAX_DURATION.as_secs_f64(),
                    "a duration longer than {} seconds",
                    MAX_DURATION.as_secs()
                );
                number.clear();
                components += 1;
            }
        }
    }
    ensure!(number.is_empty(), "a duration number without a unit");
    ensure!(components > 0, "a duration has at least one component");
    ensure!(!in_time || last_unit > 1, "a T with no time component");
    Ok(std::time::Duration::from_secs_f64(secs))
}

/// A duration as xsd:duration in whole seconds, the form clients read most reliably.
pub fn format_duration(d: std::time::Duration) -> String {
    format!("PT{}S", d.as_secs())
}

/// An xsd:dateTime; one with no zone is read as UTC, as ONVIF devices do.
pub fn parse_datetime(text: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    let t = text.trim();
    ensure!(
        !t.is_empty() && t.len() <= MAX_TIME_TEXT,
        "a dateTime is 1-{MAX_TIME_TEXT} characters"
    );
    if let Ok(d) = chrono::DateTime::parse_from_rfc3339(t) {
        return Ok(d.with_timezone(&chrono::Utc));
    }
    let naive = chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S%.f")
        .context("not an xsd:dateTime")?;
    Ok(naive.and_utc())
}

pub fn format_datetime(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A finite float attribute, or None when absent.
pub fn float_attr(e: &Element, name: &str) -> Result<Option<f64>> {
    match e.attr(name) {
        None => Ok(None),
        Some(v) => {
            let f: f64 = v
                .trim()
                .parse()
                .with_context(|| format!("{name} is not a number"))?;
            ensure!(f.is_finite(), "{name} is not finite");
            Ok(Some(f))
        }
    }
}

/// An xsd:boolean's text.
pub fn parse_bool(text: &str) -> Option<bool> {
    match text.trim() {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

pub(crate) fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_default()
}

pub(crate) fn n(v: &Value, k: &str, default: u64) -> u64 {
    v[k].as_u64().unwrap_or(default)
}

pub(crate) fn b(v: &Value, k: &str, default: bool) -> bool {
    v[k].as_bool().unwrap_or(default)
}

pub(crate) fn items<'a>(v: &'a Value, k: &str) -> impl Iterator<Item = &'a Value> {
    v[k].as_array().into_iter().flatten().take(MAX_ITEMS)
}

pub fn device_information(v: &Value) -> String {
    format!(
        "<tds:GetDeviceInformationResponse><tds:Manufacturer>{}</tds:Manufacturer><tds:Model>{}</tds:Model><tds:FirmwareVersion>{}</tds:FirmwareVersion><tds:SerialNumber>{}</tds:SerialNumber><tds:HardwareId>{}</tds:HardwareId></tds:GetDeviceInformationResponse>",
        esc(s(v, "manufacturer")),
        esc(s(v, "model")),
        esc(s(v, "firmware_version")),
        esc(s(v, "serial_number")),
        esc(s(v, "hardware_id"))
    )
}

pub fn scopes(v: &Value) -> String {
    scopes_with(v, &[])
}

/// GetScopes: the model's scopes as Fixed, then the configurable ones clients have set.
pub fn scopes_with(v: &Value, configurable: &[String]) -> String {
    let mut out = String::from("<tds:GetScopesResponse>");
    let fixed = items(v, "scopes").map(|s| ("Fixed", s.as_str().unwrap_or_default()));
    for (def, scope) in fixed.chain(configurable.iter().map(|s| ("Configurable", s.as_str()))) {
        out.push_str(&format!(
            "<tds:Scopes><tt:ScopeDef>{def}</tt:ScopeDef><tt:ScopeItem>{}</tt:ScopeItem></tds:Scopes>",
            esc(scope)
        ));
    }
    out.push_str("</tds:GetScopesResponse>");
    out
}

pub fn hostname(name: &str, from_dhcp: bool) -> String {
    format!(
        "<tds:GetHostnameResponse><tds:HostnameInformation><tt:FromDHCP>{from_dhcp}</tt:FromDHCP><tt:Name>{}</tt:Name></tds:HostnameInformation></tds:GetHostnameResponse>",
        esc(name)
    )
}

pub fn network_interfaces(v: &Value) -> String {
    let mut out = String::from("<tds:GetNetworkInterfacesResponse>");
    for i in items(v, "interfaces") {
        let dhcp = b(i, "dhcp", false);
        let address = format!(
            "<tt:Address>{}</tt:Address><tt:PrefixLength>{}</tt:PrefixLength>",
            esc(s(i, "ipv4_address")),
            n(i, "prefix_length", 24)
        );
        out.push_str(&format!(
            "<tds:NetworkInterfaces token=\"{}\"><tt:Enabled>{}</tt:Enabled><tt:Info><tt:Name>{}</tt:Name><tt:HwAddress>{}</tt:HwAddress><tt:MTU>{}</tt:MTU></tt:Info><tt:IPv4><tt:Enabled>true</tt:Enabled><tt:Config>{}<tt:DHCP>{dhcp}</tt:DHCP></tt:Config></tt:IPv4></tds:NetworkInterfaces>",
            esc(s(i, "token")),
            b(i, "enabled", true),
            esc(s(i, "name")),
            esc(s(i, "mac")),
            n(i, "mtu", 1500),
            if dhcp {
                format!("<tt:FromDHCP>{address}</tt:FromDHCP>")
            } else {
                format!("<tt:Manual>{address}</tt:Manual>")
            }
        ));
    }
    out.push_str("</tds:GetNetworkInterfacesResponse>");
    out
}

pub(crate) fn resolution(w: u64, h: u64) -> String {
    format!("<tt:Resolution><tt:Width>{w}</tt:Width><tt:Height>{h}</tt:Height></tt:Resolution>")
}

/// The multicast block a video encoder configuration must carry (unused: NetGet streams nothing).
pub const MULTICAST: &str = "<tt:Multicast><tt:Address><tt:Type>IPv4</tt:Type><tt:IPv4Address>0.0.0.0</tt:IPv4Address></tt:Address><tt:Port>0</tt:Port><tt:TTL>1</tt:TTL><tt:AutoStart>false</tt:AutoStart></tt:Multicast>";

/// The video source a profile's source token names, as `video_source_token` (default
/// `video_source`) — escaped.
pub fn source_of(p: &Value) -> String {
    match s(p, "video_source_token") {
        "" => "video_source".to_string(),
        t => esc(t),
    }
}

/// A VideoSourceConfiguration for an (escaped) source token, under `tag`; Media and Media2 share
/// its token, `vsc_<source>`.
pub fn video_source_configuration(tag: &str, source: &str, w: u64, h: u64) -> String {
    format!(
        "<{tag} token=\"vsc_{source}\"><tt:Name>{source}</tt:Name><tt:UseCount>1</tt:UseCount><tt:SourceToken>{source}</tt:SourceToken><tt:Bounds x=\"0\" y=\"0\" width=\"{w}\" height=\"{h}\"/></{tag}>"
    )
}

pub fn profiles(v: &Value) -> String {
    let mut out = String::from("<trt:GetProfilesResponse>");
    for p in items(v, "profiles") {
        let token = esc(s(p, "token"));
        let source = source_of(p);
        let (w, h) = (n(p, "width", 1920), n(p, "height", 1080));
        let fps = n(p, "framerate", 25);
        let encoding = match s(p, "encoding") {
            "" => "H264",
            e => e,
        };
        let h264 = if encoding == "H264" {
            format!("<tt:H264><tt:GovLength>{fps}</tt:GovLength><tt:H264Profile>Main</tt:H264Profile></tt:H264>")
        } else {
            String::new()
        };
        // A profile the model says can pan, tilt and zoom carries the device's one PTZ
        // configuration, which is how clients (Home Assistant among them) learn it has PTZ.
        let ptz = if b(p, "ptz", false) {
            super::ptz::configuration("tt:PTZConfiguration")
        } else {
            String::new()
        };
        out.push_str(&format!(
            "<trt:Profiles token=\"{token}\" fixed=\"true\"><tt:Name>{}</tt:Name>{}<tt:VideoEncoderConfiguration token=\"vec_{token}\"><tt:Name>{token}</tt:Name><tt:UseCount>1</tt:UseCount><tt:Encoding>{}</tt:Encoding>{}<tt:Quality>{}</tt:Quality><tt:RateControl><tt:FrameRateLimit>{fps}</tt:FrameRateLimit><tt:EncodingInterval>1</tt:EncodingInterval><tt:BitrateLimit>{}</tt:BitrateLimit></tt:RateControl>{h264}{}<tt:SessionTimeout>PT60S</tt:SessionTimeout></tt:VideoEncoderConfiguration>{ptz}</trt:Profiles>",
            esc(match s(p, "name") { "" => s(p, "token"), name => name }),
            video_source_configuration("tt:VideoSourceConfiguration", &source, w, h),
            esc(encoding),
            resolution(w, h),
            n(p, "quality", 5),
            n(p, "bitrate", 4096),
            MULTICAST,
        ));
    }
    out.push_str("</trt:GetProfilesResponse>");
    out
}

pub fn video_sources(v: &Value) -> String {
    let mut out = String::from("<trt:GetVideoSourcesResponse>");
    for src in items(v, "sources") {
        out.push_str(&format!(
            "<trt:VideoSources token=\"{}\"><tt:Framerate>{}</tt:Framerate>{}</trt:VideoSources>",
            esc(s(src, "token")),
            n(src, "framerate", 25),
            resolution(n(src, "width", 1920), n(src, "height", 1080))
        ));
    }
    out.push_str("</trt:GetVideoSourcesResponse>");
    out
}

/// GetStreamUriResponse or GetSnapshotUriResponse.
pub fn media_uri(operation: &str, v: &Value) -> String {
    format!(
        "<trt:{operation}Response><trt:MediaUri><tt:Uri>{}</tt:Uri><tt:InvalidAfterConnect>{}</tt:InvalidAfterConnect><tt:InvalidAfterReboot>{}</tt:InvalidAfterReboot><tt:Timeout>PT{}S</tt:Timeout></trt:MediaUri></trt:{operation}Response>",
        esc(s(v, "uri")),
        b(v, "invalid_after_connect", false),
        b(v, "invalid_after_reboot", false),
        n(v, "timeout_secs", 60)
    )
}

/// The GetCapabilities categories a NetGet device has, in the schema's element order. Media2
/// has no category: GetCapabilities predates it, and clients find it through GetServices.
pub const CATEGORIES: &[&str] = &["Device", "Events", "Imaging", "Media", "PTZ"];

/// GetCapabilities for the services NetGet serves whose category is in `wanted`, at `base`
/// (`http://host:port`).
pub fn capabilities(base: &str, wanted: &[&str]) -> String {
    let base = esc(base);
    let mut out = String::from("<tds:GetCapabilitiesResponse><tds:Capabilities>");
    for category in CATEGORIES.iter().filter(|c| wanted.contains(c)) {
        out.push_str(&match *category {
            "Device" => format!("<tt:Device><tt:XAddr>{base}{DEVICE_PATH}</tt:XAddr></tt:Device>"),
            "Events" => format!("<tt:Events><tt:XAddr>{base}{EVENTS_PATH}</tt:XAddr><tt:WSSubscriptionPolicySupport>false</tt:WSSubscriptionPolicySupport><tt:WSPullPointSupport>true</tt:WSPullPointSupport><tt:WSPausableSubscriptionManagerInterfaceSupport>false</tt:WSPausableSubscriptionManagerInterfaceSupport></tt:Events>"),
            "Imaging" => format!("<tt:Imaging><tt:XAddr>{base}{IMAGING_PATH}</tt:XAddr></tt:Imaging>"),
            "Media" => format!("<tt:Media><tt:XAddr>{base}{MEDIA_PATH}</tt:XAddr><tt:StreamingCapabilities><tt:RTPMulticast>false</tt:RTPMulticast><tt:RTP_TCP>true</tt:RTP_TCP><tt:RTP_RTSP_TCP>true</tt:RTP_RTSP_TCP></tt:StreamingCapabilities></tt:Media>"),
            _ => format!("<tt:PTZ><tt:XAddr>{base}{PTZ_PATH}</tt:XAddr></tt:PTZ>"),
        });
    }
    out.push_str("</tds:Capabilities></tds:GetCapabilitiesResponse>");
    out
}

/// Every service a NetGet device has: namespace and path. GetServices lists exactly these.
pub const SERVICES: &[(&str, &str)] = &[
    (TDS, DEVICE_PATH),
    (TRT, MEDIA_PATH),
    (TR2, MEDIA2_PATH),
    (TPTZ, PTZ_PATH),
    (TEV, EVENTS_PATH),
    (TIMG, IMAGING_PATH),
];

pub fn services(base: &str) -> String {
    let mut out = String::from("<tds:GetServicesResponse>");
    for (ns, path) in SERVICES {
        out.push_str(&format!(
            "<tds:Service><tds:Namespace>{ns}</tds:Namespace><tds:XAddr>{}{path}</tds:XAddr><tds:Version><tt:Major>2</tt:Major><tt:Minor>40</tt:Minor></tds:Version></tds:Service>",
            esc(base)
        ));
    }
    out.push_str("</tds:GetServicesResponse>");
    out
}

pub fn system_date_and_time(now: chrono::DateTime<chrono::Utc>) -> String {
    system_date_and_time_as(now, "Manual", "UTC0", false)
}

/// GetSystemDateAndTime with the settings a SetSystemDateAndTime last made: `date_time_type`
/// is Manual or NTP, `tz` a POSIX TZ string.
pub fn system_date_and_time_as(
    now: chrono::DateTime<chrono::Utc>,
    date_time_type: &str,
    tz: &str,
    daylight_savings: bool,
) -> String {
    use chrono::{Datelike, Timelike};
    let dt = format!(
        "<tt:Time><tt:Hour>{}</tt:Hour><tt:Minute>{}</tt:Minute><tt:Second>{}</tt:Second></tt:Time><tt:Date><tt:Year>{}</tt:Year><tt:Month>{}</tt:Month><tt:Day>{}</tt:Day></tt:Date>",
        now.hour(),
        now.minute(),
        now.second(),
        now.year(),
        now.month(),
        now.day()
    );
    format!(
        "<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime><tt:DateTimeType>{}</tt:DateTimeType><tt:DaylightSavings>{daylight_savings}</tt:DaylightSavings><tt:TimeZone><tt:TZ>{}</tt:TZ></tt:TimeZone><tt:UTCDateTime>{dt}</tt:UTCDateTime><tt:LocalDateTime>{dt}</tt:LocalDateTime></tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>",
        esc(date_time_type),
        esc(tz)
    )
}

// ---- the client side ------------------------------------------------------------------------

/// A WS-Security header carrying a PasswordDigest UsernameToken.
pub fn security_header(username: &str, password: &str, nonce: &[u8], created: &str) -> String {
    format!(
        "<wsse:Security xmlns:wsse=\"{WSSE}\" xmlns:wsu=\"{WSU}\" env:mustUnderstand=\"true\"><wsse:UsernameToken><wsse:Username>{}</wsse:Username><wsse:Password Type=\"{PASSWORD_DIGEST}\">{}</wsse:Password><wsse:Nonce EncodingType=\"{BASE64_BINARY}\">{}</wsse:Nonce><wsu:Created>{}</wsu:Created></wsse:UsernameToken></wsse:Security>",
        esc(username),
        password_digest(nonce, created, password),
        base64::engine::general_purpose::STANDARD.encode(nonce),
        esc(created)
    )
}

/// A SOAP 1.2 request envelope, with a header when `security` is given.
pub fn request_envelope(security: Option<&str>, body: &str) -> String {
    request_envelope_with(security, None, body)
}

/// WS-Addressing headers for one request: a fresh MessageID, To (the full URL) and Action. The
/// Events bindings are WS-Addressing ones, and devices answer Renew with a RelatesTo, so some
/// (onvif_simple_server) refuse a WS-BaseNotification request without a MessageID.
pub fn addressing(to: &str, action: &str) -> String {
    format!(
        "<wsa:MessageID>urn:uuid:{}</wsa:MessageID><wsa:To>{}</wsa:To><wsa:Action>{}</wsa:Action>",
        uuid::Uuid::new_v4(),
        esc(to),
        esc(action)
    )
}

/// A request envelope with WS-Security and WS-Addressing headers, either optional.
pub fn request_envelope_with(
    security: Option<&str>,
    addressing: Option<&str>,
    body: &str,
) -> String {
    let parts = format!(
        "{}{}",
        addressing.unwrap_or_default(),
        security.unwrap_or_default()
    );
    let header = if parts.is_empty() {
        String::new()
    } else {
        format!("<env:Header>{parts}</env:Header>")
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<env:Envelope {}>{header}<env:Body>{body}</env:Body></env:Envelope>",
        namespaces()
    )
}

/// A device's reply: the Body's first element, or the fault it carried as `{code, subcodes,
/// reason}`.
pub enum Reply {
    Ok(Element),
    Fault(Value),
}

fn qname_local(s: &str) -> String {
    s.trim().rsplit(':').next().unwrap_or_default().to_string()
}

pub fn parse_reply(xml: &[u8]) -> Result<Reply> {
    let env = tree(xml, MAX_RESPONSE)?;
    ensure!(
        env.name == "Envelope" && (env.ns == ENV || env.ns == ENV11),
        "the reply is not a SOAP envelope"
    );
    let body = env.child("Body").context("the reply has no Body")?;
    let el = body.children.first().context("the reply's Body is empty")?;
    if el.name != "Fault" {
        return Ok(Reply::Ok(el.clone()));
    }
    // SOAP 1.2: Code/Value with nested Subcode/Value; SOAP 1.1: faultcode and faultstring.
    if let Some(code) = el.child("Code") {
        let mut subcodes = Vec::new();
        let mut at = code.child("Subcode");
        while let Some(sc) = at {
            if subcodes.len() >= 8 {
                break;
            }
            subcodes.push(qname_local(&sc.text_of("Value").unwrap_or_default()));
            at = sc.child("Subcode");
        }
        let reason = el
            .child("Reason")
            .and_then(|r| r.text_of("Text"))
            .unwrap_or_default();
        return Ok(Reply::Fault(json!({
            "code": qname_local(&code.text_of("Value").unwrap_or_default()),
            "subcodes": subcodes,
            "reason": reason,
        })));
    }
    Ok(Reply::Fault(json!({
        "code": qname_local(&el.text_of("faultcode").unwrap_or_default()),
        "subcodes": [],
        "reason": el.text_of("faultstring").unwrap_or_default(),
    })))
}

/// The path (and query) of an XAddr URL; `None` when it is not an http(s) URL.
pub fn xaddr_path(xaddr: &str) -> Option<String> {
    let rest = xaddr
        .trim()
        .strip_prefix("http://")
        .or_else(|| xaddr.trim().strip_prefix("https://"))?;
    Some(match rest.find('/') {
        Some(i) => rest[i..].to_string(),
        None => "/".to_string(),
    })
}

fn num(e: &Element, path: &[&str]) -> Value {
    match e.path(path) {
        Some(t) => t
            .parse::<u64>()
            .map(Value::from)
            .or_else(|_| t.parse::<f64>().map(Value::from))
            .unwrap_or(Value::Null),
        None => Value::Null,
    }
}

fn opt(e: &Element, path: &[&str]) -> Value {
    e.path(path).map(Value::from).unwrap_or(Value::Null)
}

fn boolean(e: &Element, path: &[&str]) -> Value {
    match e.path(path).as_deref() {
        Some("true" | "1") => json!(true),
        Some("false" | "0") => json!(false),
        _ => Value::Null,
    }
}

/// A device's answer to `operation` as the JSON the model reads.
pub fn result_json(operation: &str, el: &Element) -> Value {
    match operation {
        "GetDeviceInformation" => json!({
            "manufacturer": opt(el, &["Manufacturer"]),
            "model": opt(el, &["Model"]),
            "firmware_version": opt(el, &["FirmwareVersion"]),
            "serial_number": opt(el, &["SerialNumber"]),
            "hardware_id": opt(el, &["HardwareId"]),
        }),
        "GetScopes" => json!({"scopes": el.children_named("Scopes").take(MAX_ITEMS).map(|s| json!({
            "uri": opt(s, &["ScopeItem"]), "definition": opt(s, &["ScopeDef"])})).collect::<Vec<_>>()}),
        "GetNetworkInterfaces" => {
            json!({"interfaces": el.children_named("NetworkInterfaces").take(MAX_ITEMS).map(|i| {
            let config = i.child("IPv4").and_then(|v| v.child("Config"));
            let addrs: Vec<Value> = config.map(|c| c.children.iter()
                .filter(|a| matches!(a.name.as_str(), "Manual" | "FromDHCP" | "LinkLocal"))
                .map(|a| json!({"source": a.name, "address": opt(a, &["Address"]), "prefix_length": num(a, &["PrefixLength"])}))
                .collect()).unwrap_or_default();
            json!({"token": i.attr("token"), "enabled": boolean(i, &["Enabled"]), "name": opt(i, &["Info", "Name"]),
                   "mac": opt(i, &["Info", "HwAddress"]), "mtu": num(i, &["Info", "MTU"]),
                   "dhcp": config.map(|c| boolean(c, &["DHCP"])).unwrap_or(Value::Null), "ipv4": addrs})
        }).collect::<Vec<_>>()})
        }
        "GetCapabilities" => {
            let mut services = Map::new();
            if let Some(c) = el.child("Capabilities") {
                for cap in &c.children {
                    if let Some(x) = cap.text_of("XAddr") {
                        services.insert(cap.name.clone(), json!(x));
                    }
                }
            }
            json!({"services": services})
        }
        "GetServices" => {
            json!({"services": el.children_named("Service").take(MAX_ITEMS).map(|s| json!({
            "namespace": opt(s, &["Namespace"]), "xaddr": opt(s, &["XAddr"]),
            "version": format!("{}.{}", s.path(&["Version", "Major"]).unwrap_or_default(), s.path(&["Version", "Minor"]).unwrap_or_default())})).collect::<Vec<_>>()})
        }
        "GetSystemDateAndTime" => {
            let t = el.child("SystemDateAndTime");
            json!({
                "date_time_type": t.map(|t| opt(t, &["DateTimeType"])).unwrap_or(Value::Null),
                "time_zone": t.map(|t| opt(t, &["TimeZone", "TZ"])).unwrap_or(Value::Null),
                "utc": t.and_then(utc_of).map(|d| json!(d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))).unwrap_or(Value::Null),
            })
        }
        "GetProfiles" => json!({"profiles": el.children_named("Profiles").take(MAX_ITEMS).map(|p| {
            let enc = p.child("VideoEncoderConfiguration");
            json!({"token": p.attr("token"), "name": opt(p, &["Name"]),
                   "video_source_token": opt(p, &["VideoSourceConfiguration", "SourceToken"]),
                   "encoding": enc.map(|e| opt(e, &["Encoding"])).unwrap_or(Value::Null),
                   "width": enc.map(|e| num(e, &["Resolution", "Width"])).unwrap_or(Value::Null),
                   "height": enc.map(|e| num(e, &["Resolution", "Height"])).unwrap_or(Value::Null),
                   "framerate": enc.map(|e| num(e, &["RateControl", "FrameRateLimit"])).unwrap_or(Value::Null),
                   "bitrate": enc.map(|e| num(e, &["RateControl", "BitrateLimit"])).unwrap_or(Value::Null)})
        }).collect::<Vec<_>>()}),
        "GetVideoSources" => {
            json!({"sources": el.children_named("VideoSources").take(MAX_ITEMS).map(|v| json!({
            "token": v.attr("token"), "framerate": num(v, &["Framerate"]),
            "width": num(v, &["Resolution", "Width"]), "height": num(v, &["Resolution", "Height"])})).collect::<Vec<_>>()})
        }
        "GetStreamUri" | "GetSnapshotUri" => json!({
            "uri": opt(el, &["MediaUri", "Uri"]),
            "timeout": opt(el, &["MediaUri", "Timeout"]),
            "invalid_after_connect": boolean(el, &["MediaUri", "InvalidAfterConnect"]),
        }),
        _ => json!({}),
    }
}

/// The UTC date and time in a SystemDateAndTime element.
pub fn utc_of(t: &Element) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::TimeZone;
    let u = t.child("UTCDateTime")?;
    let g = |p: &[&str]| u.path(p).and_then(|v| v.parse::<u32>().ok());
    let date = chrono::NaiveDate::from_ymd_opt(
        g(&["Date", "Year"])? as i32,
        g(&["Date", "Month"])?,
        g(&["Date", "Day"])?,
    )?;
    let time = chrono::NaiveTime::from_hms_opt(
        g(&["Time", "Hour"])?,
        g(&["Time", "Minute"])?,
        g(&["Time", "Second"])?,
    )?;
    chrono::Utc
        .from_local_datetime(&date.and_time(time))
        .single()
}

/// The request body a client sends for one operation.
pub fn request_body(operation: &str, args: &Value) -> Result<String> {
    let token = || -> String { esc(s(args, "profile_token")) };
    Ok(match operation {
        "GetSystemDateAndTime" | "GetDeviceInformation" | "GetScopes" | "GetNetworkInterfaces" => {
            format!("<tds:{operation}/>")
        }
        "GetCapabilities" => {
            "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>".into()
        }
        "GetServices" => {
            "<tds:GetServices><tds:IncludeCapability>false</tds:IncludeCapability></tds:GetServices>"
                .into()
        }
        "GetProfiles" | "GetVideoSources" => format!("<trt:{operation}/>"),
        "GetStreamUri" => format!(
            "<trt:GetStreamUri><trt:StreamSetup><tt:Stream>{}</tt:Stream><tt:Transport><tt:Protocol>{}</tt:Protocol></tt:Transport></trt:StreamSetup><trt:ProfileToken>{}</trt:ProfileToken></trt:GetStreamUri>",
            esc(match s(args, "stream") { "" => "RTP-Unicast", x => x }),
            esc(match s(args, "protocol") { "" => "RTSP", x => x }),
            token()
        ),
        "GetSnapshotUri" => format!(
            "<trt:GetSnapshotUri><trt:ProfileToken>{}</trt:ProfileToken></trt:GetSnapshotUri>",
            token()
        ),
        other => bail!("no request body for {other}"),
    })
}
