//! `netget::server::hdfs` — everything the HDFS NameNode, DataNode and client run on what a
//! peer sends: Hadoop IPC frames (the request header, the method header and the request
//! message of every ClientNamenodeProtocol call the NameNode decodes, the response header and
//! message the client decodes), varint-delimited messages, and DataTransferProtocol packets
//! (PLEN and HLEN checked before anything else is believed, the header's data length against the
//! payload and the bounds) and the op messages a DataNode decodes.
//!
//! What parses is checked to stay within its bound: a packet's data never longer than the
//! widest limit nor than its PLEN claims, a delimited message never past its frame. The packet
//! plan a writer follows (`transfer::packet_spans`, which an append uses to continue a partial
//! last chunk) is checked against what it promises: the packets cover exactly the bytes asked
//! for, in order and without gaps, none longer than its bound, every one keeping the block's
//! chunks aligned (the DataNode's own rule, `keeps_chunks_aligned`), and every one after the
//! first starting on a chunk boundary. The
//! protocol buffers are prost's, whose decoder counts nesting (100 levels) rather than trusting
//! the input; the corpus carries `depth_bomb`, a call whose request is ten thousand nested
//! length-delimited fields, so a decoder that recursed without that counter would overflow the
//! stack here rather than in a server.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::hdfs::proto::{common, hdfs};
use netget::server::hdfs::{rpc, transfer};
use prost::Message;

fn request(method: &str, body: &[u8]) {
    match method {
        "getFileInfo" => drop(hdfs::GetFileInfoRequestProto::decode(body)),
        "getListing" => drop(hdfs::GetListingRequestProto::decode(body)),
        "getBlockLocations" => drop(hdfs::GetBlockLocationsRequestProto::decode(body)),
        "mkdirs" => drop(hdfs::MkdirsRequestProto::decode(body)),
        "create" => drop(hdfs::CreateRequestProto::decode(body)),
        "addBlock" => drop(hdfs::AddBlockRequestProto::decode(body)),
        "complete" => drop(hdfs::CompleteRequestProto::decode(body)),
        "rename2" => drop(hdfs::Rename2RequestProto::decode(body)),
        "delete" => drop(hdfs::DeleteRequestProto::decode(body)),
        "setOwner" => drop(hdfs::SetOwnerRequestProto::decode(body)),
        "append" => drop(hdfs::AppendRequestProto::decode(body)),
        "truncate" => drop(hdfs::TruncateRequestProto::decode(body)),
        "concat" => drop(hdfs::ConcatRequestProto::decode(body)),
        "updateBlockForPipeline" => drop(hdfs::UpdateBlockForPipelineRequestProto::decode(body)),
        "updatePipeline" => drop(hdfs::UpdatePipelineRequestProto::decode(body)),
        "getAdditionalDatanode" => drop(hdfs::GetAdditionalDatanodeRequestProto::decode(body)),
        _ => drop(hdfs::GetContentSummaryRequestProto::decode(body)),
    }
}

fuzz_target!(|data: &[u8]| {
    // The connection header.
    if let Some(h) = data.get(..7) {
        let _ = rpc::parse_connection_header(h.try_into().unwrap());
    }

    // An IPC frame body as the NameNode reads it.
    if let Ok((header, rest)) = rpc::decode_request(data) {
        let _ = header.call_id;
        match header.call_id {
            rpc::CONNECTION_CONTEXT_CALL_ID => {
                let _ = rpc::decode_delimited::<common::IpcConnectionContextProto>(rest);
            }
            rpc::SASL_CALL_ID => {
                let _ = rpc::decode_delimited::<common::RpcSaslProto>(rest);
            }
            _ => {
                if let Ok((method, body)) = rpc::decode_call(rest) {
                    assert!(body.len() <= rest.len());
                    request(&method.method_name, body);
                }
            }
        }
    }

    // A response frame body as the client reads it.
    if let Ok((header, rest)) = rpc::decode_response(data) {
        let _ = rpc::response_call_id(&header);
        if let Ok((body, _)) = rpc::delimited(rest) {
            assert!(body.len() <= rest.len());
            let _ = hdfs::GetListingResponseProto::decode(body);
            let _ = hdfs::GetBlockLocationsResponseProto::decode(body);
            let _ = hdfs::AppendResponseProto::decode(body);
            let _ = hdfs::UpdateBlockForPipelineResponseProto::decode(body);
            let _ = hdfs::TruncateResponseProto::decode(body);
        }
    }

    // Delimited messages back to back, each within its buffer.
    let mut rest = data;
    for _ in 0..64 {
        match rpc::delimited(rest) {
            Ok((m, r)) => {
                assert!(m.len() + 1 <= rest.len());
                assert!(r.len() < rest.len());
                let _ = hdfs::BlockOpResponseProto::decode(m);
                let _ = hdfs::PipelineAckProto::decode(m);
                let _ = hdfs::OpReadBlockProto::decode(m);
                let _ = hdfs::OpWriteBlockProto::decode(m);
                rest = r;
            }
            Err(_) => break,
        }
    }

    // A writer's packet plan from the first bytes: an offset in a block (up to 1 GiB), a length
    // (up to a block), a chunk size the DataNode accepts and a packet bound of a chunk or more.
    if let Some(head) = data.get(..14) {
        let offset = u64::from(u32::from_be_bytes(head[0..4].try_into().unwrap())) % (1 << 30);
        let len = u64::from(u32::from_be_bytes(head[4..8].try_into().unwrap())) % (1 << 22);
        let bpc = transfer::MIN_BYTES_PER_CHECKSUM
            + u32::from(u16::from_be_bytes([head[8], head[9]]))
                % (transfer::MAX_BYTES_PER_CHECKSUM - transfer::MIN_BYTES_PER_CHECKSUM + 1);
        let max = (bpc as usize)
            .max(u32::from_be_bytes(head[10..14].try_into().unwrap()) as usize % (1 << 21));
        let spans = transfer::packet_spans(offset, len, bpc, max);
        let mut at = offset;
        for (i, (start, n)) in spans.iter().enumerate() {
            assert_eq!(*start, at, "packets are contiguous");
            assert!(*n > 0, "no empty packet");
            assert!(*n as usize <= max, "a packet within its bound");
            assert!(
                transfer::keeps_chunks_aligned(*start, *n as usize, bpc),
                "every packet keeps the chunks aligned"
            );
            if i > 0 {
                assert_eq!(
                    start % bpc as u64,
                    0,
                    "later packets start on a chunk boundary"
                );
            }
            at += n;
        }
        assert_eq!(at, offset + len, "the packets cover exactly the bytes");
        assert!(spans.len() as u64 <= len.div_ceil(bpc as u64) + 1);
    }

    // Packets back to back, under the widest bounds any chunk size allows.
    let limits = transfer::PacketLimits::widest();
    let mut rest = data;
    for _ in 0..64 {
        match transfer::decode_packet(rest, &limits) {
            Ok((p, used)) => {
                assert!(used > 0 && used <= rest.len());
                assert!(p.data.len() <= limits.max_data);
                assert!(p.sums.len() <= limits.max_sums);
                assert_eq!(p.data.len(), p.header.data_len as usize);
                for kind in [transfer::Checksum::Crc32, transfer::Checksum::Crc32c] {
                    let _ = transfer::verify(kind, 512, &p.data, &p.sums);
                }
                rest = &rest[used..];
            }
            Err(_) => break,
        }
    }
});
