//! The DataNode: DataTransferProtocol version 28 on its own listener. A connection carries ops
//! one after another (a Hadoop client reuses it after a read): READ_BLOCK streams a block's
//! bytes from the namespace in chunk-aligned packets with CRC32C checksums; WRITE_BLOCK
//! receives a block as a pipeline of one, verifying every chunk's checksum and acking every
//! packet; BLOCK_CHECKSUM answers the MD5 of the block's chunk CRCs. The model is never asked:
//! a block exists only because the NameNode described or allocated it.
use super::namespace::ReadableBlock;
use super::proto::hdfs::{
    op_write_block_proto::BlockConstructionStage, BlockChecksumTypeProto, BlockOpResponseProto,
    ChecksumProto, ClientReadStatusProto, OpBlockChecksumProto, OpBlockChecksumResponseProto,
    OpReadBlockProto, OpWriteBlockProto, PipelineAckProto, ReadOpChecksumInfoProto, Status,
};
use super::transfer::{self, op, Checksum, PacketLimits, ReadError};
use super::Hdfs;
use crate::logging::emit::Log;
use crate::server::accept_bounded::{accept_bounded, ConnectionLimiter, DEFAULT_MAX_CONNECTIONS};
use crate::server::connection::ConnectionId;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::utils::clock::Instant;
use prost::Message;
use serde_json::json;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// How long the client has to send its read status after a block.
pub const READ_STATUS_DEADLINE: Duration = Duration::from_secs(10);

pub async fn accept_loop(listener: tokio::net::TcpListener, hdfs: Arc<Hdfs>) {
    let limiter = ConnectionLimiter::new(DEFAULT_MAX_CONNECTIONS);
    let server_id = hdfs.ctx.server_id;
    let Ok(listening) = listener.local_addr() else {
        return;
    };
    loop {
        let (stream, peer, permit) = match accept_bounded(
            &listener,
            &limiter,
            b"",
            "HDFS DataNode",
            Some(&hdfs.ctx.status_tx),
        )
        .await
        {
            Ok(v) => v,
            Err(_) => break,
        };
        let _ = stream.set_nodelay(true);
        let local = stream.local_addr().unwrap_or(listening);
        let id = ConnectionId::new(hdfs.ctx.state.get_next_unified_id().await);
        let now = Instant::now();
        hdfs.ctx
            .state
            .add_connection_to_server(
                server_id,
                ConnectionState {
                    id,
                    remote_addr: peer,
                    local_addr: local,
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    last_activity: now,
                    status: ConnectionStatus::Active,
                    status_changed_at: now,
                    protocol_info: ProtocolConnectionInfo::new(json!({"role": "datanode"})),
                },
            )
            .await;
        let child = hdfs.clone();
        hdfs.ctx
            .state
            .spawn_server_task(server_id, async move {
                let _permit = permit;
                let mut c = Conn {
                    hdfs: child.clone(),
                    id,
                    peer,
                    stream,
                    ops: BTreeMap::new(),
                    sent: 0,
                    received: 0,
                };
                if let Err(e) = c.run().await {
                    Log::new(Some(&child.ctx.status_tx))
                        .debug(format!("HDFS DataNode connection {id}: {e:#}"));
                }
                c.closed().await;
                let _ = c.stream.shutdown().await;
                child
                    .ctx
                    .state
                    .update_connection_status(server_id, id, ConnectionStatus::Closed)
                    .await;
                let _ = child.ctx.status_tx.send("__UPDATE_UI__".into());
            })
            .await;
    }
}

/// One WRITE_BLOCK as its op set it up.
struct Pipeline<'a> {
    block: &'a super::proto::hdfs::ExtendedBlockProto,
    client: &'a str,
    /// The op's latestGenerationStamp.
    latest: u64,
    /// PIPELINE_SETUP_APPEND: the block's committed bytes are continued.
    append: bool,
    kind: Checksum,
    bpc: u32,
    block_size: u64,
    /// The block's committed bytes before this write.
    base: u64,
}

struct Conn {
    hdfs: Arc<Hdfs>,
    id: ConnectionId,
    peer: SocketAddr,
    stream: TcpStream,
    ops: BTreeMap<&'static str, u64>,
    sent: u64,
    received: u64,
}

/// How an op ended: keep the connection for the next op, or close it.
enum Next {
    Continue,
    Close,
}

fn response(status: Status, message: &str) -> BlockOpResponseProto {
    BlockOpResponseProto {
        status: status as i32,
        message: (!message.is_empty()).then(|| message.to_string()),
        ..Default::default()
    }
}

impl Conn {
    fn who(&self) -> String {
        format!("DataNode connection {} from {}", self.id, self.peer)
    }

    fn outcome(&self, op: &str, decision: &str, detail: &str) {
        self.hdfs.outcome(&self.who(), op, "", decision, detail);
    }

    async fn closed(&self) {
        self.hdfs
            .ctx
            .state
            .update_connection_stats(
                self.hdfs.ctx.server_id,
                self.id,
                Some(self.received),
                Some(self.sent),
                None,
                None,
            )
            .await;
        if self.ops.is_empty() {
            return;
        }
        let list: Vec<String> = self.ops.iter().map(|(o, n)| format!("{o}={n}")).collect();
        Log::new(Some(&self.hdfs.ctx.status_tx)).info(format!(
            "HDFS {} closed: {} ({} bytes out, {} bytes in)",
            self.who(),
            list.join(" "),
            self.sent,
            self.received
        ));
    }

    async fn send(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        tokio::time::timeout(
            self.hdfs.settings.deadlines.frame,
            self.stream.write_all(bytes),
        )
        .await
        .map_err(|_| anyhow::anyhow!("the client did not take the data in time"))??;
        self.sent += bytes.len() as u64;
        Ok(())
    }

    async fn reply(&mut self, r: &BlockOpResponseProto) -> anyhow::Result<()> {
        self.send(&r.encode_length_delimited_to_vec()).await
    }

    /// Refuse an op: an error response, then the connection closes.
    async fn refuse(&mut self, op: &str, status: Status, why: &str) -> anyhow::Result<Next> {
        self.outcome(
            op,
            "protocol_refusal",
            &format!("{why}; answered {}", status.as_str_name()),
        );
        self.reply(&response(status, why)).await?;
        Ok(Next::Close)
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        let deadlines = self.hdfs.settings.deadlines;
        let mut idle = deadlines.header;
        let mut first = true;
        loop {
            let (version, code, body) =
                match transfer::read_op(&mut self.stream, idle, deadlines.frame).await {
                    Ok(v) => v,
                    Err(ReadError::Closed) => return Ok(()),
                    Err(ReadError::Idle) => {
                        let (what, secs) = if first {
                            ("no first op", deadlines.header.as_secs())
                        } else {
                            ("no next op", deadlines.op_idle.as_secs())
                        };
                        self.outcome(
                            "op",
                            "protocol_refusal",
                            &format!("{what} within {secs} s; closed"),
                        );
                        return Ok(());
                    }
                    Err(ReadError::Timeout) => {
                        self.outcome(
                            "op",
                            "protocol_refusal",
                            &format!(
                            "an op's header did not arrive within {} s of its first byte; closed",
                            deadlines.frame.as_secs()
                        ),
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        self.outcome("op", "protocol_refusal", &format!("{e}; closed"));
                        return Ok(());
                    }
                };
            idle = deadlines.op_idle;
            first = false;
            self.received += 3 + body.len() as u64;
            if version != transfer::DATA_TRANSFER_VERSION {
                self.outcome(
                    "op",
                    "protocol_refusal",
                    &format!(
                        "Version Mismatch (Expected: {}, Received: {version}); closed",
                        transfer::DATA_TRANSFER_VERSION
                    ),
                );
                let _ = self
                    .reply(&response(
                        Status::ErrorInvalid,
                        &format!(
                            "Version Mismatch (Expected: {}, Received: {version})",
                            transfer::DATA_TRANSFER_VERSION
                        ),
                    ))
                    .await;
                return Ok(());
            }
            let name = op::name(code);
            *self.ops.entry(name).or_default() += 1;
            let next = match code {
                op::READ_BLOCK => self.read_block(&body).await?,
                op::WRITE_BLOCK => self.write_block(&body).await?,
                op::BLOCK_CHECKSUM => self.block_checksum(&body).await?,
                _ => {
                    self.refuse(
                        name,
                        Status::ErrorUnsupported,
                        &format!("{name} ({code}) is not supported by this DataNode"),
                    )
                    .await?
                }
            };
            if let Next::Close = next {
                return Ok(());
            }
        }
    }

    fn readable(
        &self,
        b: &super::proto::hdfs::ExtendedBlockProto,
    ) -> Result<ReadableBlock, String> {
        self.hdfs.ns().readable_block(b)
    }

    async fn read_block(&mut self, body: &[u8]) -> anyhow::Result<Next> {
        let Ok(r) = transfer::decode_op::<OpReadBlockProto>(body) else {
            return self
                .refuse(
                    "READ_BLOCK",
                    Status::ErrorInvalid,
                    "a malformed OpReadBlockProto",
                )
                .await;
        };
        let b = r.header.base_header.block.clone();
        let block = match self.readable(&b) {
            Ok(v) => v,
            Err(why) => return self.refuse("READ_BLOCK", Status::ErrorInvalid, &why).await,
        };
        if r.offset > block.len {
            return self
                .refuse(
                    "READ_BLOCK",
                    Status::ErrorInvalid,
                    &format!(
                        "Offset {} and length {} don't match block {} (blockLen {})",
                        r.offset, r.len, b.block_id, block.len
                    ),
                )
                .await;
        }
        let end = r.offset.saturating_add(r.len).min(block.len);
        let checksums = r.send_checksums.unwrap_or(true);
        let kind = if checksums {
            Checksum::Crc32c
        } else {
            Checksum::Null
        };
        let bpc = transfer::BYTES_PER_CHECKSUM;
        let start = r.offset / bpc as u64 * bpc as u64;
        self.reply(&BlockOpResponseProto {
            status: Status::Success as i32,
            read_op_checksum_info: Some(ReadOpChecksumInfoProto {
                checksum: ChecksumProto {
                    r#type: kind.proto(),
                    bytes_per_checksum: bpc,
                },
                chunk_offset: start,
            }),
            ..Default::default()
        })
        .await?;
        // Chunk-aligned packets from the chunk holding `offset` to the end of the chunk holding
        // the last byte asked for (never past the block).
        let stop = end
            .div_ceil(bpc as u64)
            .saturating_mul(bpc as u64)
            .min(block.len);
        let mut pos = start;
        let mut seqno = 0i64;
        while pos < stop {
            let n = (stop - pos).min(transfer::SEND_PACKET_DATA as u64);
            let data = {
                let ns = self.hdfs.ns();
                ns.tree.read(block.ino, block.file_offset + pos, n as u32)
            };
            let data = match data {
                Ok(d) if d.len() as u64 == n => d,
                Ok(_) | Err(_) => {
                    // A described failing region (or the file changed under the read): end the
                    // transfer mid-block, as a DataNode does on a disk read error.
                    self.outcome(
                        "READ_BLOCK",
                        "protocol_refusal",
                        &format!(
                            "block {} could not be read at {pos}; closed mid-block",
                            b.block_id
                        ),
                    );
                    return Ok(Next::Close);
                }
            };
            self.send(&transfer::data_packet(kind, bpc, pos, seqno, false, &data))
                .await?;
            seqno += 1;
            pos += n;
        }
        self.send(&transfer::data_packet(kind, bpc, pos, seqno, true, &[]))
            .await?;
        // The client says how the read went; Hadoop's client then reuses the connection.
        match transfer::read_delimited::<ClientReadStatusProto, _>(
            &mut self.stream,
            transfer::MAX_OP_MESSAGE,
            READ_STATUS_DEADLINE,
            self.hdfs.settings.deadlines.frame,
        )
        .await
        {
            Ok(s) => {
                self.received += s.encoded_len() as u64 + 1;
                Ok(Next::Continue)
            }
            Err(_) => Ok(Next::Close),
        }
    }

    async fn block_checksum(&mut self, body: &[u8]) -> anyhow::Result<Next> {
        let Ok(r) = transfer::decode_op::<OpBlockChecksumProto>(body) else {
            return self
                .refuse(
                    "BLOCK_CHECKSUM",
                    Status::ErrorInvalid,
                    "a malformed OpBlockChecksumProto",
                )
                .await;
        };
        if let Some(o) = &r.block_checksum_options {
            if o.block_checksum_type == Some(BlockChecksumTypeProto::CompositeCrc as i32) {
                return self
                    .refuse(
                        "BLOCK_CHECKSUM",
                        Status::ErrorUnsupported,
                        "COMPOSITE_CRC is not supported; MD5CRC only",
                    )
                    .await;
            }
        }
        let b = r.header.block.clone();
        let block = match self.readable(&b) {
            Ok(v) => v,
            Err(why) => {
                return self
                    .refuse("BLOCK_CHECKSUM", Status::ErrorInvalid, &why)
                    .await
            }
        };
        let bpc = transfer::BYTES_PER_CHECKSUM;
        let mut sums = Vec::with_capacity(block.len.div_ceil(bpc as u64) as usize * 4);
        let mut pos = 0u64;
        while pos < block.len {
            let n = (block.len - pos).min(transfer::SEND_PACKET_DATA as u64);
            let data = {
                let ns = self.hdfs.ns();
                ns.tree.read(block.ino, block.file_offset + pos, n as u32)
            };
            match data {
                Ok(d) if d.len() as u64 == n => {
                    sums.extend_from_slice(&transfer::checksums(Checksum::Crc32c, bpc, &d))
                }
                _ => {
                    return self
                        .refuse(
                            "BLOCK_CHECKSUM",
                            Status::Error,
                            &format!("block {} could not be read at {pos}", b.block_id),
                        )
                        .await
                }
            }
            pos += n;
        }
        self.reply(&BlockOpResponseProto {
            status: Status::Success as i32,
            checksum_response: Some(OpBlockChecksumResponseProto {
                bytes_per_crc: bpc,
                crc_per_block: (sums.len() / 4) as u64,
                block_checksum: transfer::block_md5(&sums).to_vec(),
                crc_type: Some(Checksum::Crc32c.proto()),
                block_checksum_options: None,
            }),
            ..Default::default()
        })
        .await?;
        Ok(Next::Continue)
    }

    async fn ack(&mut self, seqno: i64, status: Status) -> anyhow::Result<()> {
        let ack = PipelineAckProto {
            seqno,
            reply: vec![status as i32],
            downstream_ack_time_nanos: Some(0),
            // Hadoop 3's header flag: the status in the low bits, no ECN.
            flag: vec![status as u32],
        };
        self.send(&ack.encode_length_delimited_to_vec()).await
    }

    async fn write_block(&mut self, body: &[u8]) -> anyhow::Result<Next> {
        let Ok(r) = transfer::decode_op::<OpWriteBlockProto>(body) else {
            return self
                .refuse(
                    "WRITE_BLOCK",
                    Status::ErrorInvalid,
                    "a malformed OpWriteBlockProto",
                )
                .await;
        };
        let append = if r.stage == BlockConstructionStage::PipelineSetupCreate as i32 {
            false
        } else if r.stage == BlockConstructionStage::PipelineSetupAppend as i32 {
            true
        } else {
            let stage = BlockConstructionStage::try_from(r.stage)
                .map(|s| s.as_str_name())
                .unwrap_or("unknown");
            return self
                .refuse(
                    "WRITE_BLOCK",
                    Status::ErrorUnsupported,
                    &format!("stage {stage} is not supported: this DataNode writes new blocks and appends to a file's last block (no pipeline recovery)"),
                )
                .await;
        };
        if !r.targets.is_empty() {
            return self
                .refuse(
                    "WRITE_BLOCK",
                    Status::ErrorUnsupported,
                    "this DataNode is the whole pipeline; it forwards to no other node",
                )
                .await;
        }
        let kind = match Checksum::from_proto(r.requested_checksum.r#type) {
            Some(k @ (Checksum::Crc32 | Checksum::Crc32c)) => k,
            _ => {
                return self
                    .refuse(
                        "WRITE_BLOCK",
                        Status::ErrorUnsupported,
                        "the checksum type is CRC32C or CRC32",
                    )
                    .await
            }
        };
        let bpc = match transfer::check_bytes_per_checksum(r.requested_checksum.bytes_per_checksum)
        {
            Ok(b) => b,
            Err(e) => {
                return self
                    .refuse("WRITE_BLOCK", Status::ErrorInvalid, &format!("{e:#}"))
                    .await
            }
        };
        let b = r.header.base_header.block.clone();
        let client = crate::utils::sanitize::token(&r.header.client_name, 256);
        let latest = r.latest_generation_stamp;
        let writable = self.hdfs.ns().writable_block(&b, &client, latest, append);
        let target = match writable {
            Ok(t) => t,
            Err(why) => return self.refuse("WRITE_BLOCK", Status::ErrorInvalid, &why).await,
        };
        // An append continues the bytes the block holds; Hadoop's DataNode refuses a replica
        // whose length is not the one the client names.
        if append && r.min_bytes_rcvd != target.base {
            return self
                .refuse(
                    "WRITE_BLOCK",
                    Status::ErrorInvalid,
                    &format!(
                        "block {} holds {} bytes, but the append expects {}",
                        b.block_id, target.base, r.min_bytes_rcvd
                    ),
                )
                .await;
        }
        self.reply(&BlockOpResponseProto {
            status: Status::Success as i32,
            first_bad_link: Some(String::new()),
            ..Default::default()
        })
        .await?;
        let limits = PacketLimits::for_chunks(kind, bpc);
        let mut data: Vec<u8> = Vec::new();
        let mut reserved = 0u64;
        let pipeline = Pipeline {
            block: &b,
            client: &client,
            latest,
            append,
            kind,
            bpc,
            block_size: target.block_size,
            base: target.base,
        };
        let result = self
            .receive(&pipeline, &limits, &mut data, &mut reserved)
            .await;
        match result {
            Ok(true) => {
                let len = data.len();
                let received = self
                    .hdfs
                    .ns()
                    .block_received(&b, &client, latest, append, data);
                if let Err(why) = received {
                    self.outcome(
                        "WRITE_BLOCK",
                        "protocol_refusal",
                        &format!("{why}; the block is dropped"),
                    );
                } else {
                    self.outcome(
                        "WRITE_BLOCK",
                        "accepted",
                        &format!(
                            "block {} received whole: {len} bytes{}, every chunk's {} verified",
                            b.block_id,
                            if append {
                                format!(" appended after {}", target.base)
                            } else {
                                String::new()
                            },
                            kind.name()
                        ),
                    );
                }
                Ok(Next::Close)
            }
            Ok(false) | Err(_) => {
                self.hdfs.ns().release(reserved);
                result.map(|_| Next::Close)
            }
        }
    }

    /// Read a block's packets until the last one; `Ok(true)` when it arrived whole. `data`
    /// holds the block's bytes from `base` (what an append continues; 0 for a new block).
    async fn receive(
        &mut self,
        w: &Pipeline<'_>,
        limits: &PacketLimits,
        data: &mut Vec<u8>,
        reserved: &mut u64,
    ) -> anyhow::Result<bool> {
        let (b, kind, bpc, base) = (w.block, w.kind, w.bpc, w.base);
        let deadlines = self.hdfs.settings.deadlines;
        loop {
            let p = match transfer::read_packet(
                &mut self.stream,
                limits,
                deadlines.packet,
                deadlines.frame,
            )
            .await
            {
                Ok(p) => p,
                Err(ReadError::Closed) => {
                    self.outcome(
                        "WRITE_BLOCK",
                        "protocol_refusal",
                        &format!(
                            "the client closed before block {}'s last packet; dropped",
                            b.block_id
                        ),
                    );
                    return Ok(false);
                }
                Err(ReadError::Idle) => {
                    self.outcome(
                        "WRITE_BLOCK",
                        "protocol_refusal",
                        &format!(
                            "no packet of block {} within {} s; dropped and closed",
                            b.block_id,
                            deadlines.packet.as_secs()
                        ),
                    );
                    return Ok(false);
                }
                Err(e) => {
                    self.outcome(
                        "WRITE_BLOCK",
                        "protocol_refusal",
                        &format!("{e}; block {} dropped and closed", b.block_id),
                    );
                    return Ok(false);
                }
            };
            self.received += 6 + p.sums.len() as u64 + p.data.len() as u64;
            let h = &p.header;
            if h.seqno == -1 {
                // A heartbeat.
                self.ack(-1, Status::Success).await?;
                continue;
            }
            if let Err(chunk) = transfer::verify(kind, bpc, &p.data, &p.sums) {
                self.outcome(
                    "WRITE_BLOCK",
                    "protocol_refusal",
                    &format!("packet {} of block {}: chunk {chunk} fails its {} check; answered ERROR_CHECKSUM and dropped the block", h.seqno, b.block_id, kind.name()),
                );
                self.ack(h.seqno, Status::ErrorChecksum).await?;
                return Ok(false);
            }
            let offset = h.offset_in_block as u64;
            let have = base + data.len() as u64;
            // Contiguous, or rewriting the tail of a partial chunk sent before (after hflush),
            // never the bytes an append continues from; a packet that starts inside a chunk
            // (an append's first) ends by that chunk's end, its checksum over its own bytes.
            if offset < base
                || offset > have
                || have - offset >= bpc as u64 && offset != have
                || !transfer::keeps_chunks_aligned(offset, p.data.len(), bpc)
            {
                self.outcome(
                    "WRITE_BLOCK",
                    "protocol_refusal",
                    &format!(
                        "packet {} of block {} starts at {offset}, but {have} bytes are in",
                        h.seqno, b.block_id
                    ),
                );
                self.ack(h.seqno, Status::ErrorInvalid).await?;
                return Ok(false);
            }
            let end = offset + p.data.len() as u64;
            if end > w.block_size {
                self.outcome(
                    "WRITE_BLOCK",
                    "protocol_refusal",
                    &format!(
                        "block {} would grow past its block size {}",
                        b.block_id, w.block_size
                    ),
                );
                self.ack(h.seqno, Status::ErrorInvalid).await?;
                return Ok(false);
            }
            let grow = end.saturating_sub(have);
            if grow > 0 && !self.hdfs.ns().reserve(grow) {
                self.outcome(
                    "WRITE_BLOCK",
                    "protocol_refusal",
                    &format!("block {}: the overlay is full; answered ERROR", b.block_id),
                );
                self.ack(h.seqno, Status::Error).await?;
                return Ok(false);
            }
            *reserved += grow;
            data.truncate((offset - base) as usize);
            data.extend_from_slice(&p.data);
            // The block may have been abandoned or its file deleted meanwhile.
            let still = self
                .hdfs
                .ns()
                .writable_block(b, w.client, w.latest, w.append);
            if let Err(why) = still {
                self.outcome(
                    "WRITE_BLOCK",
                    "protocol_refusal",
                    &format!("{why}; answered ERROR"),
                );
                self.ack(h.seqno, Status::Error).await?;
                return Ok(false);
            }
            self.ack(h.seqno, Status::Success).await?;
            if h.last_packet_in_block {
                return Ok(true);
            }
        }
    }
}
