//! Db2 client: NetGet speaks DRDA to IBM Db2 or Apache Derby and the model decides what SQL to
//! run. See `AGENTS.md` beside this file.
//!
//! Two tasks per connection, both registered with the client so `stop_client` ends them:
//!
//! * the **session** owns the socket. It runs the handshake before `connect` returns, then
//!   executes one action at a time — the model's, or one injected from the dashboard or MCP —
//!   as a DRDA request and its whole reply, and turns the reply into an event.
//! * the **turns** task asks the model about each event and hands the actions it answers with
//!   back to the session. Each event carries the number of model turns that led to it; past
//!   [`MAX_FOLLOWUP_DEPTH`] the model is not asked again.
//!
//! Fail closed: a refused login fails `connect` and the model is never asked anything; an LLM
//! failure sends nothing; a reply this client cannot read, a timeout or a server that hangs up
//! ends the connection with an error rather than inventing a result.
pub mod actions;
pub mod wire;

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::Db2ClientProtocol;
use wire::{cp, Object, Sqlca};

/// How many model turns may follow from one another before the chain stops.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
/// How long a whole reply may take. A statement can wait on a lock (Derby's default lock
/// timeout is a minute), so this is generous; past it the connection is given up.
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_REPLY_TIMEOUT_SECS: u64 = 3600;
/// How long the TCP connect may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Apache Derby admits only product ids containing its own client's `DNC`; Db2 accepts any.
pub const DEFAULT_PRODUCT_ID: &str = "DNC10170";
pub const DEFAULT_AUTOCOMMIT: bool = false;
/// The port a remote address without one is given: Db2's default instance port.
pub const DEFAULT_PORT: u16 = 50000;
/// Statements remembered for the unit of work reported on commit or rollback.
const MAX_UOW_STATEMENTS: usize = 16;
/// Each remembered statement is cut to this many bytes.
const UOW_STATEMENT_BYTES: usize = 200;
/// Events waiting for the model.
const TURNS: usize = 64;
/// The read buffer never holds more than one DSS at its bound plus one read.
const MAX_READ_BUFFER: usize = wire::MAX_DSS_BYTES + 64 * 1024;

/// Reply messages after which the conversation cannot continue.
const FATAL_REPLIES: &[u16] = &[cp::SYNTAXRM, cp::PRCCNVRM, cp::AGNPRMRM, cp::MGRLVLRM];

/// What the server said about itself during the handshake.
#[derive(Debug, Clone, Default)]
pub struct ServerInfo {
    pub server_class: String,
    pub server_name: String,
    pub server_release: String,
    pub product_id: String,
}

/// One DRDA connection, after or during the handshake.
pub struct Conn {
    stream: TcpStream,
    buf: Vec<u8>,
    pub repr: wire::Repr,
    timeout: Duration,
    pub bytes_out: usize,
    package: Option<wire::Package>,
    uow: Vec<String>,
    autocommit: bool,
}

/// What one action produced: the event to raise.
pub type Done = (&'static EventType, Value);

fn find(objs: &[Object], codepoint: u16) -> Option<&Object> {
    objs.iter().find(|o| o.codepoint == codepoint)
}

fn text_param(data: &[u8], codepoint: u16) -> Result<String> {
    Ok(wire::param(data, codepoint)?
        .map(wire::from_ebcdic)
        .map(|s| crate::utils::sanitize::line_field(&s))
        .unwrap_or_default())
}

fn remember(uow: &mut Vec<String>, sql: &str) {
    if uow.len() == MAX_UOW_STATEMENTS {
        uow.remove(0);
    }
    uow.push(crate::utils::truncate::truncate_with_suffix(
        sql,
        UOW_STATEMENT_BYTES,
        "...",
    ));
}

impl Conn {
    pub fn new(stream: TcpStream, timeout: Duration, autocommit: bool) -> Self {
        Self {
            stream,
            buf: Vec::with_capacity(32 * 1024),
            repr: wire::Repr::default(),
            timeout,
            bytes_out: 0,
            package: None,
            uow: Vec::new(),
            autocommit,
        }
    }

    /// Send one command and read every DSS of its reply chain.
    pub async fn exchange(&mut self, parts: Vec<(u8, Vec<u8>)>) -> Result<Vec<Object>> {
        // Correlators distinguish the commands of one request chain. Each chain here is one
        // command, so each starts at 1, as Derby's and IBM's clients do; Derby answers a chain
        // that starts anywhere else with correlator 1 regardless.
        let corr = 1;
        let bytes = wire::command(corr, &parts);
        let timeout = self.timeout;
        tokio::time::timeout(timeout, async {
            self.stream.write_all(&bytes).await?;
            self.stream.flush().await?;
            self.bytes_out += bytes.len();
            let mut out = Vec::new();
            let mut total = 0usize;
            for count in 1.. {
                let dss = self.next_dss().await?;
                ensure!(
                    count <= wire::MAX_REPLY_DSS,
                    "the reply runs past {} DSSes; refused",
                    wire::MAX_REPLY_DSS
                );
                total += dss.payload.len();
                ensure!(
                    total <= wire::MAX_REPLY_BYTES,
                    "the reply runs past {} bytes; refused",
                    wire::MAX_REPLY_BYTES
                );
                ensure!(
                    dss.correlator == corr,
                    "a reply DSS carries correlator {} where the request had {corr}",
                    dss.correlator
                );
                ensure!(
                    matches!(dss.dss_type, wire::DSS_RPYDSS | wire::DSS_OBJDSS),
                    "a reply DSS of type {} (neither a reply nor an object)",
                    dss.dss_type
                );
                for obj in wire::objects(&dss.payload)? {
                    match obj.codepoint {
                        cp::TYPDEFNAM => self.repr.set_name(&obj.data)?,
                        cp::TYPDEFOVR => self.repr.set_overrides(&obj.data)?,
                        _ => out.push(obj),
                    }
                }
                if !dss.chained {
                    break;
                }
            }
            Ok(out)
        })
        .await
        .map_err(|_| anyhow!("no complete reply within {}s", timeout.as_secs()))?
    }

    async fn next_dss(&mut self) -> Result<wire::Dss> {
        let mut chunk = vec![0u8; 32 * 1024];
        loop {
            if let Some(dss) = wire::take_dss(&mut self.buf)? {
                return Ok(dss);
            }
            let n = self.stream.read(&mut chunk).await?;
            ensure!(n > 0, "the server closed the connection mid-reply");
            self.buf.extend_from_slice(&chunk[..n]);
            ensure!(
                self.buf.len() <= MAX_READ_BUFFER,
                "the server sent more than {MAX_READ_BUFFER} bytes without completing a DSS"
            );
        }
    }

    /// The first reply message at severity ERROR or worse, as a sentence.
    fn refusal(objs: &[Object]) -> Result<Option<(u16, String)>> {
        for o in objs {
            let is_reply_message = matches!(o.codepoint >> 8, 0x12 | 0x22);
            if !is_reply_message {
                continue;
            }
            let svrcod = wire::severity(&o.data)?;
            if svrcod < 8 {
                continue;
            }
            let mut msg = format!("{} at severity {svrcod}", wire::name_of(o.codepoint));
            if let Some([code]) = wire::param(&o.data, cp::SYNERRCD)? {
                msg.push_str(&format!(", syntax error code 0x{code:02X}"));
            }
            if let Some([a, b]) = wire::param(&o.data, cp::CODPNT)? {
                let c = u16::from_be_bytes([*a, *b]);
                msg.push_str(&format!(", about {}", wire::name_of(c)));
            }
            return Ok(Some((o.codepoint, msg)));
        }
        Ok(None)
    }

    fn sqlca(&self, objs: &[Object]) -> Result<Option<Sqlca>> {
        let mut found = None;
        for o in objs.iter().filter(|o| o.codepoint == cp::SQLCARD) {
            if let Some(ca) = wire::parse_sqlcard(&o.data, &self.repr)? {
                // The most serious SQLCA wins: an error over a warning over success.
                let worse = match &found {
                    None => true,
                    Some(Sqlca { sqlcode, .. }) => ca.sqlcode < 0 && *sqlcode >= 0,
                };
                if worse {
                    found = Some(ca);
                }
            }
        }
        Ok(found)
    }

    /// The SQL or DRDA failure in a reply, as a `db2_error` event; `Err` when the conversation
    /// cannot go on.
    fn failure(&self, objs: &[Object], operation: &str, sql: Option<&str>) -> Result<Option<Done>> {
        let rolled_back = find(objs, cp::ABNUOWRM).is_some();
        if let Some(ca) = self.sqlca(objs)? {
            if ca.sqlcode < 0 {
                let mut data = json!({
                    "operation": operation,
                    "sqlcode": ca.sqlcode,
                    "sqlstate": ca.sqlstate,
                    "message_tokens": ca.tokens,
                    "message": format!("the server refused it with SQLCODE {} (SQLSTATE {})", ca.sqlcode, ca.sqlstate),
                    "rolled_back": rolled_back,
                });
                if let Some(sql) = sql {
                    data["sql"] = json!(sql);
                }
                return Ok(Some((&actions::ERROR_EVENT, data)));
            }
        }
        if let Some((codepoint, message)) = Self::refusal(objs)? {
            if FATAL_REPLIES.contains(&codepoint) {
                bail!(
                    "{operation}: the server answered {message}; the conversation cannot continue"
                );
            }
            let mut data = json!({
                "operation": operation,
                "reply_message": wire::name_of(codepoint),
                "message": format!("the server answered {message}"),
                "rolled_back": rolled_back,
            });
            if let Some(sql) = sql {
                data["sql"] = json!(sql);
            }
            return Ok(Some((&actions::ERROR_EVENT, data)));
        }
        Ok(None)
    }

    fn error(operation: &str, sql: Option<&str>, message: String) -> Done {
        let mut data = json!({ "operation": operation, "message": message });
        if let Some(sql) = sql {
            data["sql"] = json!(sql);
        }
        (&actions::ERROR_EVENT, data)
    }

    /// EXCSAT, ACCSEC, SECCHK, ACCRDB. Any refusal is an error: the caller fails `connect`.
    pub async fn handshake(
        &mut self,
        database: &str,
        user: &str,
        password: Option<&str>,
        product_id: &str,
        crrtkn: Vec<u8>,
    ) -> Result<ServerInfo> {
        let mut info = ServerInfo::default();

        let objs = self
            .exchange(vec![(wire::DSS_RQSDSS, wire::excsat(product_id)?)])
            .await?;
        let rd = find(&objs, cp::EXCSATRD).ok_or_else(|| match Self::refusal(&objs) {
            Ok(Some((_, m))) => anyhow!("EXCSAT refused: {m}"),
            _ => anyhow!("the server did not answer EXCSAT with EXCSATRD"),
        })?;
        info.server_class = text_param(&rd.data, cp::SRVCLSNM)?;
        info.server_name = text_param(&rd.data, cp::SRVNAM)?;
        info.server_release = text_param(&rd.data, cp::SRVRLSLV)?;
        if let Some(levels) = wire::param(&rd.data, cp::MGRLVLLS)? {
            for pair in levels.chunks_exact(4) {
                let manager = u16::from_be_bytes([pair[0], pair[1]]);
                let level = u16::from_be_bytes([pair[2], pair[3]]);
                if manager == cp::SQLAM {
                    ensure!(
                        level >= wire::SQLAM_LEVEL,
                        "the server speaks SQLAM level {level}; this client reads level {}",
                        wire::SQLAM_LEVEL
                    );
                }
            }
        }

        let secmec = if password.is_some() {
            wire::SECMEC_USRIDPWD
        } else {
            wire::SECMEC_USRIDONL
        };
        let objs = self
            .exchange(vec![(wire::DSS_RQSDSS, wire::accsec(secmec, database)?)])
            .await?;
        let rd = find(&objs, cp::ACCSECRD).ok_or_else(|| match Self::refusal(&objs) {
            Ok(Some((_, m))) => anyhow!("ACCSEC refused: {m}"),
            _ => anyhow!("the server did not answer ACCSEC with ACCSECRD"),
        })?;
        let offered: Vec<u16> = wire::params(&rd.data)?
            .into_iter()
            .filter(|(c, _)| *c == cp::SECMEC)
            .flat_map(|(_, v)| {
                v.chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect::<Vec<_>>()
            })
            .collect();
        ensure!(
            offered.contains(&secmec),
            "the server does not accept security mechanism {secmec} ({}); it offered {offered:?}. \
             This client implements USRIDPWD (3) and USRIDONL (4) only",
            if secmec == 3 {
                "user id and password"
            } else {
                "user id only"
            }
        );
        if let Some([code]) = wire::param(&rd.data, cp::SECCHKCD)? {
            ensure!(
                *code == 0,
                "ACCSEC refused: SECCHKCD 0x{code:02X} ({})",
                wire::secchkcd_meaning(*code)
            );
        }

        let objs = self
            .exchange(vec![(
                wire::DSS_RQSDSS,
                wire::secchk(secmec, database, user, password)?,
            )])
            .await?;
        let rm = find(&objs, cp::SECCHKRM).ok_or_else(|| match Self::refusal(&objs) {
            Ok(Some((_, m))) => anyhow!("SECCHK refused: {m}"),
            _ => anyhow!("the server did not answer SECCHK with SECCHKRM"),
        })?;
        let code = match wire::param(&rm.data, cp::SECCHKCD)? {
            Some([c]) => *c,
            _ => bail!("SECCHKRM carries no SECCHKCD"),
        };
        let svrcod = wire::severity(&rm.data)?;
        ensure!(
            code == 0 && svrcod < 8,
            "login refused: SECCHKCD 0x{code:02X} ({}) at severity {svrcod} decision=refused",
            wire::secchkcd_meaning(code)
        );

        let objs = self
            .exchange(vec![(
                wire::DSS_RQSDSS,
                wire::accrdb(database, product_id, &crrtkn)?,
            )])
            .await?;
        let Some(rm) = find(&objs, cp::ACCRDBRM) else {
            let why = match (Self::refusal(&objs)?, self.sqlca(&objs)?) {
                (Some((_, m)), Some(ca)) => format!(
                    "{m}; SQLCODE {} SQLSTATE {} {:?}",
                    ca.sqlcode, ca.sqlstate, ca.tokens
                ),
                (Some((_, m)), None) => m,
                (None, _) => "no ACCRDBRM".to_string(),
            };
            bail!("opening database {database:?} refused: {why} decision=refused");
        };
        let svrcod = wire::severity(&rm.data)?;
        ensure!(
            svrcod < 8,
            "opening database {database:?} refused: ACCRDBRM at severity {svrcod} decision=refused"
        );
        info.product_id = text_param(&rm.data, cp::PRDID)?;
        if let Some(name) = wire::param(&rm.data, cp::TYPDEFNAM)? {
            self.repr.set_name(name)?;
        }
        if let Some(ovr) = wire::param(&rm.data, cp::TYPDEFOVR)? {
            self.repr.set_overrides(ovr)?;
        }
        if let Some(ca) = self.sqlca(&objs)? {
            ensure!(
                ca.sqlcode >= 0,
                "opening database {database:?} failed: SQLCODE {} SQLSTATE {}",
                ca.sqlcode,
                ca.sqlstate
            );
        }
        self.package = Some(wire::Package::new(database)?);
        Ok(info)
    }

    fn package(&self) -> Result<&wire::Package> {
        self.package.as_ref().context("the database is not open")
    }

    /// Run one action. `Ok` carries the event to raise (including SQL errors); `Err` means
    /// the connection is unusable.
    pub async fn perform(&mut self, name: &str, data: &Value) -> Result<Done> {
        let sql = data.get("sql").and_then(Value::as_str).unwrap_or_default();
        match name {
            "execute_statement" => self.execute_statement(sql).await,
            "execute_query" => {
                let max_rows =
                    data.get("max_rows")
                        .and_then(Value::as_u64)
                        .unwrap_or(wire::DEFAULT_MAX_ROWS as u64) as usize;
                self.execute_query(sql, max_rows.min(wire::MAX_ROWS_LIMIT))
                    .await
            }
            "commit" => self.end_unit_of_work(true).await,
            "rollback" => self.end_unit_of_work(false).await,
            other => bail!("no such Db2 operation {other}"),
        }
    }

    async fn execute_statement(&mut self, sql: &str) -> Result<Done> {
        let parts = wire::excsqlimm(self.package()?, sql)?;
        let objs = self.exchange(parts).await?;
        if let Some(fail) = self.failure(&objs, "execute_statement", Some(sql))? {
            if find(&objs, cp::ABNUOWRM).is_some() {
                self.uow.clear();
            }
            return Ok(fail);
        }
        let ca = self.sqlca(&objs)?.unwrap_or_default();
        remember(&mut self.uow, sql);
        let mut data = json!({
            "sql": sql,
            "sqlcode": ca.sqlcode,
            "sqlstate": ca.sqlstate.trim(),
            "row_count": ca.row_count(),
            "message_tokens": ca.tokens,
            "committed": false,
        });
        if self.autocommit {
            match self.end_unit_of_work(true).await? {
                (event, _) if std::ptr::eq(event, &*actions::TRANSACTION_RESULT_EVENT) => {
                    data["committed"] = json!(true)
                }
                failed => return Ok(failed),
            }
        }
        Ok((&actions::STATEMENT_RESULT_EVENT, data))
    }

    async fn execute_query(&mut self, sql: &str, max_rows: usize) -> Result<Done> {
        let parts = wire::prpsqlstt(self.package()?, sql)?;
        let objs = self.exchange(parts).await?;
        if let Some(fail) = self.failure(&objs, "prepare", Some(sql))? {
            return Ok(fail);
        }
        let Some(dard) = find(&objs, cp::SQLDARD) else {
            return Ok(Self::error(
                "prepare",
                Some(sql),
                "the server described no result (no SQLDARD)".into(),
            ));
        };
        let (ca, columns) = match wire::parse_sqldard(&dard.data, &self.repr) {
            Ok(v) => v,
            Err(e) => return Ok(Self::error("prepare", Some(sql), format!("{e:#}"))),
        };
        if let Some(ca) = ca.filter(|ca| ca.sqlcode < 0) {
            return Ok((
                &actions::ERROR_EVENT,
                json!({"operation": "prepare", "sql": sql, "sqlcode": ca.sqlcode,
                       "sqlstate": ca.sqlstate, "message_tokens": ca.tokens,
                       "message": format!("the server refused it with SQLCODE {}", ca.sqlcode)}),
            ));
        }
        if columns.is_empty() {
            return Ok(Self::error(
                "prepare",
                Some(sql),
                "the statement returns no rows; run it with execute_statement".into(),
            ));
        }
        remember(&mut self.uow, sql);

        let objs = self.exchange(wire::opnqry(self.package()?)).await?;
        if let Some(fail) = self.failure(&objs, "open_query", Some(sql))? {
            return Ok(fail);
        }
        let Some(rm) = find(&objs, cp::OPNQRYRM) else {
            return Ok(Self::error(
                "open_query",
                Some(sql),
                "the server did not open the query (no OPNQRYRM)".into(),
            ));
        };
        let qryinsid = wire::param(&rm.data, cp::QRYINSID)?
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        let dsc: Vec<u8> = objs
            .iter()
            .filter(|o| o.codepoint == cp::QRYDSC)
            .flat_map(|o| o.data.iter().copied())
            .collect();
        let fields = match wire::parse_qrydsc(&dsc) {
            Ok(f) if f.len() == columns.len() => f,
            Ok(f) => {
                self.close_query(&qryinsid).await?;
                return Ok(Self::error(
                    "open_query",
                    Some(sql),
                    format!(
                        "the row layout has {} fields where the description has {} columns",
                        f.len(),
                        columns.len()
                    ),
                ));
            }
            Err(e) => {
                self.close_query(&qryinsid).await?;
                return Ok(Self::error("open_query", Some(sql), format!("{e:#}")));
            }
        };

        let mut data: Vec<u8> = Vec::new();
        let mut received = 0usize;
        let mut ended = false;
        let mut failed: Option<Sqlca> = None;
        absorb(
            &objs,
            &mut data,
            &mut received,
            &mut ended,
            &mut failed,
            &self.repr,
        )?;

        let mut rows: Vec<Value> = Vec::new();
        let mut warnings: Vec<Value> = Vec::new();
        let mut truncated = false;
        let mut done = false;
        let mut continues = 0usize;
        let mut decode_error: Option<String> = None;
        'fetch: loop {
            let mut pos = 0;
            while pos < data.len() {
                match wire::decode_row(&data[pos..], &fields, &self.repr) {
                    Err(e) => {
                        decode_error = Some(format!("{e:#}"));
                        break 'fetch;
                    }
                    Ok(None) => break,
                    Ok(Some((item, used))) => {
                        pos += used;
                        match item {
                            wire::RowItem::Row(values, warning) => {
                                if rows.len() == max_rows {
                                    truncated = true;
                                    break 'fetch;
                                }
                                rows.push(wire::row_object(&columns, values));
                                if let Some(w) = warning {
                                    warnings.push(w.to_json());
                                }
                            }
                            wire::RowItem::End(_) => {
                                done = true;
                                break 'fetch;
                            }
                            wire::RowItem::Failed(ca) => {
                                failed = Some(ca);
                                break 'fetch;
                            }
                            wire::RowItem::Empty => {}
                        }
                    }
                }
            }
            data.drain(..pos);
            if failed.is_some() {
                break;
            }
            if ended {
                if !data.is_empty() {
                    decode_error = Some(format!(
                        "the query ended with {} bytes of an unfinished row",
                        data.len()
                    ));
                }
                done = true;
                break;
            }
            continues += 1;
            if continues > wire::MAX_CONTINUES {
                decode_error = Some(format!(
                    "the answer set took more than {} query blocks; refused",
                    wire::MAX_CONTINUES
                ));
                break;
            }
            let objs = self
                .exchange(wire::cntqry(self.package()?, &qryinsid))
                .await?;
            if find(&objs, cp::QRYNOPRM).is_some() {
                // The server already closed it: nothing more will come.
                done = true;
                break;
            }
            if let Some(fail) = self.failure(&objs, "fetch", Some(sql))? {
                return Ok(fail);
            }
            absorb(
                &objs,
                &mut data,
                &mut received,
                &mut ended,
                &mut failed,
                &self.repr,
            )?;
            if received > wire::MAX_RESULT_BYTES {
                decode_error = Some(format!(
                    "the answer set passed {} bytes; refused",
                    wire::MAX_RESULT_BYTES
                ));
                break;
            }
        }
        if !done && failed.is_none() {
            self.close_query(&qryinsid).await?;
        }
        if let Some(ca) = failed {
            return Ok((
                &actions::ERROR_EVENT,
                json!({"operation": "fetch", "sql": sql, "sqlcode": ca.sqlcode,
                       "sqlstate": ca.sqlstate, "message_tokens": ca.tokens,
                       "message": format!("the query failed after {} rows with SQLCODE {}", rows.len(), ca.sqlcode)}),
            ));
        }
        if let Some(message) = decode_error {
            return Ok(Self::error("fetch", Some(sql), message));
        }
        let data = json!({
            "sql": sql,
            "columns": columns.iter().map(wire::Column::to_json).collect::<Vec<_>>(),
            "row_count": rows.len(),
            "rows": rows,
            "truncated": truncated,
            "warnings": warnings,
        });
        if self.autocommit {
            let (event, failed) = self.end_unit_of_work(true).await?;
            if !std::ptr::eq(event, &*actions::TRANSACTION_RESULT_EVENT) {
                return Ok((event, failed));
            }
        }
        Ok((&actions::QUERY_RESULT_EVENT, data))
    }

    /// CLSQRY, tolerating a query the server already closed.
    async fn close_query(&mut self, qryinsid: &[u8]) -> Result<()> {
        if qryinsid.is_empty() {
            return Ok(());
        }
        let objs = self
            .exchange(wire::clsqry(self.package()?, qryinsid))
            .await?;
        if let Some((codepoint, message)) = Self::refusal(&objs)? {
            ensure!(
                !FATAL_REPLIES.contains(&codepoint),
                "closing the query: {message}"
            );
        }
        Ok(())
    }

    async fn end_unit_of_work(&mut self, commit: bool) -> Result<Done> {
        let operation = if commit { "commit" } else { "rollback" };
        let parts = if commit {
            wire::rdbcmm()
        } else {
            wire::rdbrllbck()
        };
        let objs = self.exchange(parts).await?;
        if let Some(fail) = self.failure(&objs, operation, None)? {
            return Ok(fail);
        }
        let disposition = match find(&objs, cp::ENDUOWRM) {
            Some(rm) => match wire::param(&rm.data, cp::UOWDSP)? {
                Some([1]) => "committed",
                Some([2]) => "rolled_back",
                _ => operation_outcome(commit),
            },
            None => operation_outcome(commit),
        };
        let ca = self.sqlca(&objs)?.unwrap_or_default();
        let statements = std::mem::take(&mut self.uow);
        Ok((
            &actions::TRANSACTION_RESULT_EVENT,
            json!({
                "operation": operation,
                "outcome": disposition,
                "statements": statements,
                "sqlcode": ca.sqlcode,
            }),
        ))
    }
}

fn operation_outcome(commit: bool) -> &'static str {
    if commit {
        "committed"
    } else {
        "rolled_back"
    }
}

/// Take a reply's answer-set data: QRYDTA bytes, and whether the query ended.
fn absorb(
    objs: &[Object],
    data: &mut Vec<u8>,
    received: &mut usize,
    ended: &mut bool,
    failed: &mut Option<Sqlca>,
    repr: &wire::Repr,
) -> Result<()> {
    for o in objs {
        match o.codepoint {
            cp::QRYDTA => {
                *received += o.data.len();
                ensure!(
                    *received <= wire::MAX_RESULT_BYTES,
                    "the answer set passed {} bytes; refused",
                    wire::MAX_RESULT_BYTES
                );
                data.extend_from_slice(&o.data);
            }
            cp::ENDQRYRM => *ended = true,
            cp::SQLCARD if *ended => {
                if let Some(ca) = wire::parse_sqlcard(&o.data, repr)? {
                    if ca.sqlcode < 0 {
                        *failed = Some(ca);
                    }
                }
            }
            cp::EXTDTA => {
                bail!("the answer set carries LOB data (EXTDTA), which this client does not read")
            }
            _ => {}
        }
    }
    Ok(())
}

async fn resolve(raw: &str) -> Result<String> {
    let raw = raw.trim();
    ensure!(
        !raw.is_empty(),
        "the Db2 client needs a remote_addr (host:port); refusing to connect without one"
    );
    if raw.parse::<SocketAddr>().is_ok() {
        return Ok(raw.to_string());
    }
    if raw
        .rsplit_once(':')
        .is_some_and(|(h, p)| !h.contains(':') && p.parse::<u16>().is_ok())
    {
        return Ok(raw.to_string());
    }
    Ok(format!("{}:{DEFAULT_PORT}", raw.trim_matches(['[', ']'])))
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let string = |key: &str| -> Result<Option<String>> {
        Ok(params
            .map(|p| p.get_optional_string(key))
            .transpose()?
            .flatten())
    };
    let database = string("database")?
        .filter(|d| !d.trim().is_empty())
        .context("the Db2 client needs the database startup parameter (the RDB name)")?;
    let user = string("username")?
        .filter(|u| !u.is_empty())
        .context("the Db2 client needs the username startup parameter")?;
    let password = string("password")?;
    let product_id = string("product_id")?.unwrap_or_else(|| DEFAULT_PRODUCT_ID.to_string());
    let autocommit = params
        .map(|p| p.get_optional_bool("autocommit"))
        .transpose()?
        .flatten()
        .unwrap_or(DEFAULT_AUTOCOMMIT);
    let timeout_secs = params
        .map(|p| p.get_optional_u64("reply_timeout_secs"))
        .transpose()?
        .flatten()
        .unwrap_or(REPLY_TIMEOUT.as_secs());
    ensure!(
        (1..=MAX_REPLY_TIMEOUT_SECS).contains(&timeout_secs),
        "reply_timeout_secs is 1..={MAX_REPLY_TIMEOUT_SECS}"
    );

    let target = resolve(&ctx.remote_addr).await?;
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&target))
        .await
        .map_err(|_| {
            anyhow!(
                "connecting to {target} took more than {}s",
                CONNECT_TIMEOUT.as_secs()
            )
        })?
        .with_context(|| format!("cannot connect to Db2 at {target}"))?;
    let local = stream.local_addr()?;
    let peer = stream.peer_addr()?;
    let mut conn = Conn::new(stream, Duration::from_secs(timeout_secs), autocommit);
    let token = wire::correlation_token(local, rand::random());
    let log = Log::new(Some(&ctx.status_tx));
    let info = match conn
        .handshake(&database, &user, password.as_deref(), &product_id, token)
        .await
    {
        Ok(info) => info,
        Err(e) => {
            log.warn(format!(
                "Db2 client {}: handshake with {peer} failed: {e:#} decision=fail_closed_handshake",
                ctx.client_id
            ));
            return Err(e);
        }
    };
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    log.info(format!(
        "Db2 client {} connected to {peer} database {database:?} as {user} ({} {}, {})",
        ctx.client_id, info.server_class, info.server_release, conn.repr.typdefnam
    ));
    let _ = ctx.status_tx.send("__UPDATE_UI__".into());

    // Registered before the connected turn can run, so the operator can reach the client
    // while that turn is parked on a manual rule.
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (event_tx, event_rx) = mpsc::channel::<(Event, u32)>(TURNS);
    let (internal_tx, internal) = mpsc::channel::<(Value, u32)>(TURNS);
    let _ = event_tx.try_send((
        Event::new(
            &actions::CONNECTED_EVENT,
            json!({
                "remote_addr": peer.to_string(),
                "database": database,
                "user": user,
                "server_class": info.server_class,
                "server_release": info.server_release,
                "server_product_id": info.product_id,
                "data_representation": conn.repr.typdefnam,
            }),
        ),
        0,
    ));
    let dispatcher = tokio::spawn(run_turns(ctx.clone(), event_rx, internal_tx));
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let result = run_session(&mut conn, &session_ctx, external, internal, event_tx).await;
        dispatcher_abort.abort();
        let _ = conn.stream.shutdown().await;
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx)).warn(format!(
                    "Db2 client {} ended: {e:#} decision=connection_failed",
                    session_ctx.client_id
                ));
                ClientStatus::Error(e.to_string())
            }
        };
        session_ctx
            .state
            .update_client_status(session_ctx.client_id, status)
            .await;
        session_ctx
            .state
            .remove_client_handle(session_ctx.client_id)
            .await;
        let _ = session_ctx.status_tx.send("__UPDATE_UI__".into());
    });
    ctx.state.register_client_task(ctx.client_id, task).await;
    Ok(local)
}

fn reply(command: Option<ClientCommand>, outcome: ClientSendOutcome) {
    if let Some(c) = command {
        crate::client::command_support::reply(c, Ok(outcome));
    }
}

/// Execute actions one at a time until the connection ends.
async fn run_session(
    conn: &mut Conn,
    ctx: &ConnectContext,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<(Value, u32)>,
    events: mpsc::Sender<(Event, u32)>,
) -> Result<()> {
    let protocol = Db2ClientProtocol;
    let mut idle = [0u8; 1024];
    loop {
        let (action, depth, command) = tokio::select! {
            c = external.recv() => match c {
                Some(c) => {
                    ctx.state.record_access_log(AccessLogOwner::Client(ctx.client_id.as_u32()), "Db2",
                        None, "injected_action", c.action.clone(), vec![]).await;
                    (c.action.clone(), 0, Some(c))
                }
                None => return Ok(()),
            },
            a = internal.recv() => match a {
                Some((a, d)) => (a, d, None),
                None => return Ok(()),
            },
            r = conn.stream.read(&mut idle) => {
                return match r {
                    Ok(0) => Err(anyhow!("the server closed the connection")),
                    Ok(n) => Err(anyhow!("the server sent {n} bytes with no request outstanding")),
                    Err(e) => Err(e.into()),
                };
            }
        };
        let (name, data) = match protocol.execute_action(action) {
            Ok(ClientActionResult::Disconnect) => {
                reply(command, ClientSendOutcome::Disconnected);
                return Ok(());
            }
            Ok(ClientActionResult::Custom { name, data }) => (name, data),
            Ok(_) => {
                reply(
                    command,
                    ClientSendOutcome::Executed {
                        detail: "nothing to send".into(),
                    },
                );
                continue;
            }
            Err(e) => {
                Log::new(Some(&ctx.status_tx)).warn(format!(
                    "Db2 client {}: action refused: {e:#}",
                    ctx.client_id
                ));
                reply(
                    command,
                    ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    },
                );
                continue;
            }
        };
        let before = conn.bytes_out;
        let (event_type, payload) = match conn.perform(&name, &data).await {
            Ok(done) => done,
            Err(e) => {
                reply(
                    command,
                    ClientSendOutcome::Rejected {
                        error: format!("{e:#}"),
                    },
                );
                return Err(e);
            }
        };
        reply(
            command,
            ClientSendOutcome::Sent {
                bytes_sent: conn.bytes_out - before,
            },
        );
        tracing::info!(
            "Db2 client {} {name} -> {} (depth {depth})",
            ctx.client_id,
            event_type.id
        );
        if events
            .try_send((Event::new(event_type, payload), depth))
            .is_err()
        {
            Log::new(Some(&ctx.status_tx)).warn(format!(
                "Db2 client {}: {} events are waiting for the model; this one is dropped \
                 decision=turn_queue_full",
                ctx.client_id, TURNS
            ));
        }
        let _ = ctx.status_tx.send("__UPDATE_UI__".into());
    }
}

/// Ask the model about each event, in order, and hand its actions to the session.
async fn run_turns(
    ctx: ConnectContext,
    mut events: mpsc::Receiver<(Event, u32)>,
    internal: mpsc::Sender<(Value, u32)>,
) {
    let protocol = Db2ClientProtocol;
    while let Some((event, depth)) = events.recv().await {
        if depth >= MAX_FOLLOWUP_DEPTH {
            Log::new(Some(&ctx.status_tx)).warn(format!(
                "Db2 client {} not asking the model about {}: {depth} turns deep \
                 decision=followup_depth",
                ctx.client_id,
                event.id()
            ));
            continue;
        }
        let instruction = ctx
            .state
            .get_instruction_for_client(ctx.client_id)
            .await
            .unwrap_or_default();
        let memory = ctx
            .state
            .get_memory_for_client(ctx.client_id)
            .await
            .unwrap_or_default();
        match call_llm_for_client(
            &ctx.llm_client,
            &ctx.state,
            ctx.client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            &protocol,
            &ctx.status_tx,
        )
        .await
        {
            Ok(result) => {
                if let Some(memory) = result.memory_updates {
                    ctx.state.set_memory_for_client(ctx.client_id, memory).await;
                }
                tracing::info!(
                    "Db2 client {} {} decision={} actions={}",
                    ctx.client_id,
                    event.id(),
                    if result.actions.is_empty() {
                        "model_silent"
                    } else {
                        "model_actions"
                    },
                    result.actions.len()
                );
                for action in result.actions {
                    if internal.send((action, depth + 1)).await.is_err() {
                        return;
                    }
                }
            }
            // Fail closed: nothing is sent on the model's behalf when it cannot be asked.
            Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!(
                "Db2 client {} {}: {e:#} decision=fail_closed_llm_error",
                ctx.client_id,
                event.id()
            )),
        }
    }
}
