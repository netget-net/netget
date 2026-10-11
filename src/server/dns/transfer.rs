//! Zone transfers: AXFR (RFC 5936) and IXFR (RFC 1995), built from the model's structured
//! answer and split into as many DNS messages as the zone needs.
//!
//! The model answers a `dns_zone_transfer` event with `send_dns_zone` (the whole zone) or
//! `send_dns_ixfr` (the changes since the client's serial). Neither executor builds wire
//! bytes, because a zone does not fit one message — hickory refuses to encode past 65535 bytes,
//! the most a TCP DNS message can carry. The executors validate the action and hand it back;
//! this module turns it into the record sequence the RFCs define, and `mod.rs` signs it (for a
//! `dnssec_zone`) and cuts it into messages with [`split_into_messages`].

use anyhow::{bail, Context, Result};
use hickory_proto::op::{Header, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use serde_json::Value;

use super::records::{parse_name, record_from_json, records_from_json};

/// Most records one transfer may carry, SOAs and changes included. Far past any zone a model
/// would invent, and the bound on what one answer can make the server hold and sign.
pub const MAX_ZONE_RECORDS: usize = 10_000;

/// A transfer message is filled to about this many bytes before the next one starts. Well
/// under the 65535 a TCP message can carry, as BIND does, so one oversize record cannot push a
/// message past the limit.
pub const TRANSFER_MESSAGE_BYTES: usize = 16 * 1024;

/// The zone, its SOA and its other records, from a `send_dns_zone` action.
pub struct Zone {
    pub origin: Name,
    pub soa: Record,
    pub records: Vec<Record>,
}

fn origin_of(action: &Value) -> Result<Name> {
    let zone = action
        .get("zone")
        .and_then(|z| z.as_str())
        .context("a zone transfer answer needs 'zone', the zone's name, e.g. \"example.com.\"")?;
    parse_name(zone, None)
}

fn soa_of(action: &Value, origin: &Name) -> Result<Record> {
    let mut soa_json = action
        .get("soa")
        .cloned()
        .context("a zone transfer answer needs 'soa': the zone's SOA record")?;
    if let Some(obj) = soa_json.as_object_mut() {
        obj.entry("type").or_insert(Value::from("SOA"));
        obj.entry("name").or_insert(Value::from("@"));
    }
    let soa = record_from_json(&soa_json, Some(origin), Some(origin)).context("soa")?;
    if soa.record_type() != RecordType::SOA {
        bail!("'soa' must be an SOA record");
    }
    if soa.name() != origin {
        bail!(
            "the SOA belongs at the zone apex {origin}, not at {}",
            soa.name()
        );
    }
    Ok(soa)
}

/// The SOA's serial.
pub fn serial_of(soa: &Record) -> Option<u32> {
    match soa.data() {
        Some(RData::SOA(s)) => Some(s.serial()),
        _ => None,
    }
}

fn with_serial(soa: &Record, serial: u32) -> Record {
    let mut r = soa.clone();
    if let Some(RData::SOA(s)) = soa.data() {
        r.set_data(Some(RData::SOA(SOA::new(
            s.mname().clone(),
            s.rname().clone(),
            serial,
            s.refresh(),
            s.retry(),
            s.expire(),
            s.minimum(),
        ))));
    }
    r
}

fn in_zone(records: &[Record], origin: &Name, what: &str) -> Result<()> {
    for r in records {
        if !origin.zone_of(r.name()) {
            bail!(
                "{what}: {} {} is outside the zone {origin}",
                r.name(),
                r.record_type()
            );
        }
        if r.record_type() == RecordType::SOA {
            bail!("{what}: the zone's SOA goes in 'soa', not among the records");
        }
    }
    Ok(())
}

/// Read and check a `send_dns_zone` action.
pub fn zone_from_action(action: &Value) -> Result<Zone> {
    let origin = origin_of(action)?;
    let soa = soa_of(action, &origin)?;
    let records = records_from_json(
        action.get("records"),
        Some(&origin),
        None,
        "records",
        MAX_ZONE_RECORDS - 2,
    )?;
    in_zone(&records, &origin, "records")?;
    Ok(Zone {
        origin,
        soa,
        records,
    })
}

/// The AXFR answer sequence: SOA, every record, SOA (RFC 5936 §2.2).
pub fn axfr_sequence(zone: &Zone) -> Vec<Record> {
    let mut out = Vec::with_capacity(zone.records.len() + 2);
    out.push(zone.soa.clone());
    out.extend(zone.records.iter().cloned());
    out.push(zone.soa.clone());
    out
}

/// Read a `send_dns_ixfr` action into the IXFR answer sequence for a client at
/// `client_serial` (RFC 1995 §4): the new SOA; then, per change, the SOA it starts from, the
/// records it deletes, the SOA it ends at and the records it adds; then the new SOA again.
/// With no changes the answer is the new SOA alone, which tells a client at that serial it is
/// current.
pub fn ixfr_from_action(action: &Value, client_serial: u32) -> Result<(Name, Vec<Record>)> {
    let origin = origin_of(action)?;
    let soa = soa_of(action, &origin)?;
    let new_serial = serial_of(&soa).unwrap_or_default();
    let changes = match action.get("changes") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(c)) => c.clone(),
        Some(other) => bail!("'changes' must be an array, got {other}"),
    };
    let mut out = vec![soa.clone()];
    if changes.is_empty() {
        return Ok((origin, out));
    }
    let mut from = client_serial;
    let mut total = 2;
    for (i, change) in changes.iter().enumerate() {
        let to = change
            .get("serial")
            .and_then(|s| s.as_u64())
            .and_then(|s| u32::try_from(s).ok())
            .with_context(|| format!("changes[{i}] needs 'serial', the serial it ends at"))?;
        let deleted = records_from_json(
            change.get("deleted"),
            Some(&origin),
            None,
            &format!("changes[{i}].deleted"),
            MAX_ZONE_RECORDS,
        )?;
        let added = records_from_json(
            change.get("added"),
            Some(&origin),
            None,
            &format!("changes[{i}].added"),
            MAX_ZONE_RECORDS,
        )?;
        in_zone(&deleted, &origin, "deleted")?;
        in_zone(&added, &origin, "added")?;
        total += deleted.len() + added.len() + 2;
        if total > MAX_ZONE_RECORDS {
            bail!("the IXFR answer passes {MAX_ZONE_RECORDS} records");
        }
        out.push(with_serial(&soa, from));
        out.extend(deleted);
        out.push(with_serial(&soa, to));
        out.extend(added);
        from = to;
    }
    if from != new_serial {
        bail!("the last change ends at serial {from} but 'soa' says {new_serial}; they must agree");
    }
    out.push(soa);
    Ok((origin, out))
}

/// An empty response to `query`, AA set: the shell every transfer message is built in.
pub fn response_shell(query: &Message, rcode: ResponseCode) -> Message {
    let mut message = Message::new();
    let mut header = Header::new();
    header.set_id(query.id());
    header.set_message_type(MessageType::Response);
    header.set_op_code(OpCode::Query);
    header.set_authoritative(true);
    header.set_recursion_desired(query.recursion_desired());
    header.set_response_code(rcode);
    message.set_header(header);
    message
}

/// Cut `records` into transfer messages of about `target` bytes, each answering `query`. The
/// question goes in the first message only (RFC 5936 §2.2.1 permits it in the rest but nothing
/// requires it). `extra` is added to the last message — the OPT record, when the query had one.
pub fn split_into_messages(
    query: &Message,
    question: Option<&Query>,
    records: Vec<Record>,
    target: usize,
    extra: impl Fn(&mut Message),
) -> Result<Vec<Vec<u8>>> {
    let mut messages = Vec::new();
    let mut current = response_shell(query, ResponseCode::NoError);
    if let Some(q) = question {
        current.add_query(q.clone());
    }
    let mut size = 12usize;
    let mut count = 0usize;
    let finish = |m: &mut Message, last: bool| -> Result<Vec<u8>> {
        if last {
            extra(m);
        }
        m.to_vec().context("cannot encode a zone transfer message")
    };
    let total = records.len();
    for (i, record) in records.into_iter().enumerate() {
        let len = record
            .to_bytes()
            .context("cannot encode a zone transfer record")?
            .len();
        if count > 0 && size + len > target {
            messages.push(finish(&mut current, false)?);
            current = response_shell(query, ResponseCode::NoError);
            size = 12;
            count = 0;
        }
        size += len;
        count += 1;
        current.add_answer(record);
        if i + 1 == total {
            messages.push(finish(&mut current, true)?);
            return Ok(messages);
        }
    }
    messages.push(finish(&mut current, true)?);
    Ok(messages)
}
