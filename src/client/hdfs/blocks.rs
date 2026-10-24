//! Block transfers with a DataNode: READ_BLOCK (the bytes checked against every chunk's
//! checksum before they are believed) and WRITE_BLOCK through the pipeline the NameNode named
//! (packets with CRC32C chunk checksums, at most [`MAX_UNACKED`] unacknowledged, each ack
//! checked for its sequence number and every node's status).
use crate::server::hdfs::proto::common::TokenProto;
use crate::server::hdfs::proto::hdfs::{
    op_write_block_proto::BlockConstructionStage, BaseHeaderProto, BlockOpResponseProto,
    CachingStrategyProto, ChecksumProto, ClientOperationHeaderProto, ClientReadStatusProto,
    DatanodeInfoProto, ExtendedBlockProto, LocatedBlockProto, OpReadBlockProto, OpWriteBlockProto,
    PipelineAckProto, Status, StorageTypeProto,
};
use crate::server::hdfs::transfer::{self, op, Checksum, PacketLimits};
use anyhow::{bail, ensure, Context, Result};
use prost::Message;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Packets a write may have in flight without an ack.
pub const MAX_UNACKED: usize = 8;
/// How long any DataNode step may take.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(60);
/// Packets one read may take (a 64 KiB read at 512-byte packets and then some).
pub const MAX_READ_PACKETS: usize = 1024;

/// Where a DataNode is: the address it reports, or the NameNode's host when it reports none.
pub fn datanode_addr(dn: &DatanodeInfoProto, namenode: SocketAddr) -> Result<SocketAddr> {
    let port = u16::try_from(dn.id.xfer_port).context("the DataNode's port is not a port")?;
    let ip = match dn.id.ip_addr.parse::<std::net::IpAddr>() {
        Ok(ip) if !ip.is_unspecified() => ip,
        _ => namenode.ip(),
    };
    Ok(SocketAddr::new(ip, port))
}

async fn open(addr: SocketAddr) -> Result<TcpStream> {
    let s = tokio::time::timeout(STEP_TIMEOUT, TcpStream::connect(addr))
        .await
        .context("connecting to the DataNode timed out")?
        .with_context(|| format!("connecting to the DataNode at {addr}"))?;
    let _ = s.set_nodelay(true);
    Ok(s)
}

async fn response(s: &mut TcpStream) -> Result<BlockOpResponseProto> {
    transfer::read_delimited::<BlockOpResponseProto, _>(
        s,
        transfer::MAX_OP_MESSAGE,
        STEP_TIMEOUT,
        STEP_TIMEOUT,
    )
    .await
    .map_err(|e| anyhow::anyhow!("the DataNode's response: {e}"))
}

fn refused(r: &BlockOpResponseProto) -> anyhow::Error {
    let status = Status::try_from(r.status)
        .map(|s| s.as_str_name())
        .unwrap_or("unknown");
    anyhow::anyhow!(
        "the DataNode answered {status}: {}",
        r.message.clone().unwrap_or_default()
    )
}

fn header(
    block: &ExtendedBlockProto,
    token: &TokenProto,
    client: &str,
) -> ClientOperationHeaderProto {
    ClientOperationHeaderProto {
        base_header: BaseHeaderProto {
            block: block.clone(),
            token: Some(token.clone()),
            trace_info: None,
        },
        client_name: client.to_string(),
    }
}

/// Read `len` bytes from `offset` in a block, every chunk's checksum verified.
pub async fn read(
    addr: SocketAddr,
    block: &LocatedBlockProto,
    client: &str,
    offset: u64,
    len: u64,
) -> Result<Vec<u8>> {
    let mut s = open(addr).await?;
    let request = OpReadBlockProto {
        header: header(&block.b, &block.block_token, client),
        offset,
        len,
        send_checksums: Some(true),
        caching_strategy: Some(CachingStrategyProto {
            drop_behind: None,
            readahead: None,
        }),
    };
    s.write_all(&transfer::op_request(op::READ_BLOCK, &request))
        .await?;
    let r = response(&mut s).await?;
    if r.status != Status::Success as i32 {
        return Err(refused(&r));
    }
    let info = r
        .read_op_checksum_info
        .context("the DataNode named no checksum for the read")?;
    let kind = Checksum::from_proto(info.checksum.r#type).context("an unknown checksum type")?;
    let bpc = transfer::check_bytes_per_checksum(info.checksum.bytes_per_checksum)?;
    ensure!(
        info.chunk_offset <= offset && offset - info.chunk_offset < bpc as u64,
        "the DataNode starts at {} for a read at {offset}",
        info.chunk_offset
    );
    let limits = PacketLimits::for_chunks(kind, bpc);
    let mut data = Vec::new();
    let want = (offset - info.chunk_offset + len) as usize;
    let mut expected_offset = info.chunk_offset;
    for _ in 0..MAX_READ_PACKETS {
        let p = transfer::read_packet(&mut s, &limits, STEP_TIMEOUT, STEP_TIMEOUT)
            .await
            .map_err(|e| anyhow::anyhow!("a packet from the DataNode: {e}"))?;
        ensure!(
            p.header.offset_in_block as u64 == expected_offset,
            "a packet at {} where {expected_offset} was next",
            p.header.offset_in_block
        );
        if let Err(chunk) = transfer::verify(kind, bpc, &p.data, &p.sums) {
            bail!(
                "chunk {chunk} of the packet at {} fails its {} check: the block is corrupt",
                p.header.offset_in_block,
                kind.name()
            );
        }
        expected_offset += p.data.len() as u64;
        ensure!(
            data.len() + p.data.len() <= want + bpc as usize,
            "the DataNode sent more than was asked for"
        );
        data.extend_from_slice(&p.data);
        if p.header.last_packet_in_block {
            let status = ClientReadStatusProto {
                status: if kind == Checksum::Null {
                    Status::Success
                } else {
                    Status::ChecksumOk
                } as i32,
            };
            let _ = s.write_all(&status.encode_length_delimited_to_vec()).await;
            let skip = (offset - info.chunk_offset) as usize;
            ensure!(
                data.len() >= skip + len as usize,
                "the DataNode sent {} bytes, short of the {len} asked for",
                data.len().saturating_sub(skip)
            );
            return Ok(data[skip..skip + len as usize].to_vec());
        }
    }
    bail!("the DataNode sent more than {MAX_READ_PACKETS} packets for one read")
}

/// An ack's verdict: every node's status, from `reply` or (Hadoop 3) the header flags.
fn ack_ok(a: &PipelineAckProto) -> Result<()> {
    let statuses: Vec<i32> = if a.flag.is_empty() {
        a.reply.clone()
    } else {
        // The status is the flag's low four bits.
        a.flag.iter().map(|f| (f & 0xF) as i32).collect()
    };
    ensure!(!statuses.is_empty(), "an ack with no status");
    for s in statuses {
        if s != Status::Success as i32 {
            let name = Status::try_from(s)
                .map(|s| s.as_str_name())
                .unwrap_or("unknown");
            bail!("the pipeline answered {name} for packet {}", a.seqno);
        }
    }
    Ok(())
}

async fn read_ack(s: &mut TcpStream, seqno: i64) -> Result<()> {
    let a = transfer::read_delimited::<PipelineAckProto, _>(
        s,
        transfer::MAX_OP_MESSAGE,
        STEP_TIMEOUT,
        STEP_TIMEOUT,
    )
    .await
    .map_err(|e| anyhow::anyhow!("the ack for packet {seqno}: {e}"))?;
    ensure!(
        a.seqno == seqno,
        "an ack for packet {} while packet {seqno} was next",
        a.seqno
    );
    ack_ok(&a)
}

/// How a block write begins: a new block, or the partial last block an append reopened.
#[derive(Clone, Copy, Debug)]
pub enum Stage {
    Create,
    /// PIPELINE_SETUP_APPEND: the block holds `base` bytes, and the pipeline runs under the
    /// generation stamp updateBlockForPipeline gave (`latest`).
    Append {
        base: u64,
        latest: u64,
    },
}

/// A block write whose pipeline is set up: the DataNode answered the op, and packets go next.
pub struct BlockWrite {
    stream: TcpStream,
    pub datanode: SocketAddr,
    offset: u64,
}

/// Open a block's pipeline at the first DataNode the NameNode named: WRITE_BLOCK, and its
/// answer. An append's pipeline continues from the bytes the block holds.
pub async fn open_write(
    namenode: SocketAddr,
    block: &LocatedBlockProto,
    client: &str,
    stage: Stage,
) -> Result<BlockWrite> {
    let first = block
        .locs
        .first()
        .context("the NameNode named no DataNode")?;
    let addr = datanode_addr(first, namenode)?;
    let mut s = open(addr).await?;
    let disk = StorageTypeProto::Disk as i32;
    let rest = block.locs.len().saturating_sub(1);
    let (stage_proto, base, latest) = match stage {
        Stage::Create => (BlockConstructionStage::PipelineSetupCreate, 0, 0),
        Stage::Append { base, latest } => {
            (BlockConstructionStage::PipelineSetupAppend, base, latest)
        }
    };
    let request = OpWriteBlockProto {
        header: header(&block.b, &block.block_token, client),
        targets: block.locs.iter().skip(1).cloned().collect(),
        source: None,
        stage: stage_proto as i32,
        pipeline_size: block.locs.len() as u32,
        min_bytes_rcvd: base,
        max_bytes_rcvd: base,
        latest_generation_stamp: if latest == 0 {
            block.b.generation_stamp
        } else {
            latest
        },
        requested_checksum: ChecksumProto {
            r#type: Checksum::Crc32c.proto(),
            bytes_per_checksum: transfer::BYTES_PER_CHECKSUM,
        },
        caching_strategy: Some(CachingStrategyProto {
            drop_behind: None,
            readahead: None,
        }),
        storage_type: Some(block.storage_types.first().copied().unwrap_or(disk)),
        target_storage_types: block
            .storage_types
            .iter()
            .skip(1)
            .copied()
            .chain(std::iter::repeat(disk))
            .take(rest)
            .collect(),
        allow_lazy_persist: Some(false),
        pinning: Some(false),
        target_pinnings: vec![false; rest],
        storage_id: block.storage_i_ds.first().cloned(),
        target_storage_ids: block.storage_i_ds.iter().skip(1).cloned().collect(),
    };
    s.write_all(&transfer::op_request(op::WRITE_BLOCK, &request))
        .await?;
    let r = response(&mut s).await?;
    if r.status != Status::Success as i32 {
        let bad = r.first_bad_link.clone().unwrap_or_default();
        return Err(refused(&r).context(format!("first bad link: {bad:?}")));
    }
    Ok(BlockWrite {
        stream: s,
        datanode: addr,
        offset: base,
    })
}

impl BlockWrite {
    /// Send `data` from where the block stands, then the empty last packet once every data
    /// packet is acknowledged. Packets carry CRC32C in 512-byte chunks; a block an append
    /// reopened inside a chunk gets that chunk's rest in a packet of its own, its checksum over
    /// the new bytes only. The block's length when done.
    pub async fn finish(mut self, data: &[u8]) -> Result<u64> {
        let bpc = transfer::BYTES_PER_CHECKSUM;
        let mut unacked: VecDeque<i64> = VecDeque::new();
        let mut seqno = 0i64;
        let start = self.offset;
        for (offset, len) in
            transfer::packet_spans(start, data.len() as u64, bpc, transfer::SEND_PACKET_DATA)
        {
            while unacked.len() >= MAX_UNACKED {
                let next = unacked.pop_front().expect("non-empty");
                read_ack(&mut self.stream, next).await?;
            }
            let piece = &data[(offset - start) as usize..(offset - start + len) as usize];
            self.stream
                .write_all(&transfer::data_packet(
                    Checksum::Crc32c,
                    bpc,
                    offset,
                    seqno,
                    false,
                    piece,
                ))
                .await?;
            unacked.push_back(seqno);
            seqno += 1;
            self.offset = offset + len;
        }
        while let Some(next) = unacked.pop_front() {
            read_ack(&mut self.stream, next).await?;
        }
        self.stream
            .write_all(&transfer::data_packet(
                Checksum::Crc32c,
                bpc,
                self.offset,
                seqno,
                true,
                &[],
            ))
            .await?;
        read_ack(&mut self.stream, seqno).await?;
        let _ = self.stream.shutdown().await;
        Ok(self.offset)
    }
}

/// Write a whole new block through its pipeline; the block as the NameNode should hear of it.
pub async fn write(
    namenode: SocketAddr,
    block: &LocatedBlockProto,
    client: &str,
    data: &[u8],
) -> Result<(ExtendedBlockProto, SocketAddr)> {
    let w = open_write(namenode, block, client, Stage::Create).await?;
    let addr = w.datanode;
    let len = w.finish(data).await?;
    let mut b = block.b.clone();
    b.num_bytes = Some(len);
    Ok((b, addr))
}
