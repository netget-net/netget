//! `netget::server::hdfs` — everything the HDFS NameNode, DataNode and client run on what a
//! peer sends: Hadoop IPC frames (the request header, the method header and the request
//! message of every ClientNamenodeProtocol call the NameNode decodes, the response header and
//! message the client decodes), varint-delimited messages, and DataTransferProtocol packets
//! (PLEN and HLEN checked before anything else is believed, the header's data length against the
//! payload and the bounds) and the op messages a DataNode decodes.
//!
//! What parses is checked to stay within its bound: a packet's data never longer than the
//! widest limit nor than its PLEN claims, a delimited message never past its frame. The
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
