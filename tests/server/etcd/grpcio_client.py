# The Python gRPC client (grpcio, gRPC C-core) with upb protobuf, driving NetGet's etcd server.
#
# Neither library shares a line with the server: NetGet frames HTTP/2 with hyper/h2 and protobuf
# with prost; this client's HTTP/2 is gRPC C-core's chttp2 and its protobuf is upb. The message
# types are built here from etcd's rpc.proto field numbers with protobuf's own descriptor API,
# so encoding and decoding are upb's, not anything NetGet wrote.
#
# Usage: python3 grpcio_client.py <port>. Prints one "ok <step>" line per verified step and
# exits non-zero on the first wrong answer, naming it.
import sys

import grpc
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

F = descriptor_pb2.FieldDescriptorProto
BYTES, I64, U64, BOOL, I32, MSG = (
    F.TYPE_BYTES, F.TYPE_INT64, F.TYPE_UINT64, F.TYPE_BOOL, F.TYPE_INT32, F.TYPE_MESSAGE)
OPT, REP = F.LABEL_OPTIONAL, F.LABEL_REPEATED

fdp = descriptor_pb2.FileDescriptorProto(
    name="netget_etcd_subset.proto", package="etcdserverpb", syntax="proto3")


def message(name, fields, oneofs=()):
    m = fdp.message_type.add(name=name)
    for o in oneofs:
        m.oneof_decl.add(name=o)
    for spec in fields:
        fname, number, ftype = spec[:3]
        label = spec[3] if len(spec) > 3 else OPT
        f = m.field.add(name=fname, number=number, type=ftype, label=label)
        if len(spec) > 4 and spec[4]:
            f.type_name = ".etcdserverpb." + spec[4]
        if len(spec) > 5:
            f.oneof_index = spec[5]


# Enums are carried as int32: the wire form of an enum is its varint.
message("ResponseHeader", [("cluster_id", 1, U64), ("member_id", 2, U64),
                           ("revision", 3, I64), ("raft_term", 4, U64)])
message("KeyValue", [("key", 1, BYTES), ("create_revision", 2, I64), ("mod_revision", 3, I64),
                     ("version", 4, I64), ("value", 5, BYTES), ("lease", 6, I64)])
message("RangeRequest", [("key", 1, BYTES), ("range_end", 2, BYTES), ("limit", 3, I64),
                         ("revision", 4, I64), ("sort_order", 5, I32), ("sort_target", 6, I32),
                         ("serializable", 7, BOOL), ("keys_only", 8, BOOL),
                         ("count_only", 9, BOOL)])
message("RangeResponse", [("header", 1, MSG, OPT, "ResponseHeader"),
                          ("kvs", 2, MSG, REP, "KeyValue"), ("more", 3, BOOL),
                          ("count", 4, I64)])
message("PutRequest", [("key", 1, BYTES), ("value", 2, BYTES), ("lease", 3, I64),
                       ("prev_kv", 4, BOOL), ("ignore_value", 5, BOOL),
                       ("ignore_lease", 6, BOOL)])
message("PutResponse", [("header", 1, MSG, OPT, "ResponseHeader"),
                        ("prev_kv", 2, MSG, OPT, "KeyValue")])
message("DeleteRangeRequest", [("key", 1, BYTES), ("range_end", 2, BYTES), ("prev_kv", 3, BOOL)])
message("DeleteRangeResponse", [("header", 1, MSG, OPT, "ResponseHeader"), ("deleted", 2, I64),
                                ("prev_kvs", 3, MSG, REP, "KeyValue")])
message("RequestOp", [("request_range", 1, MSG, OPT, "RangeRequest", 0),
                      ("request_put", 2, MSG, OPT, "PutRequest", 0),
                      ("request_delete_range", 3, MSG, OPT, "DeleteRangeRequest", 0)],
        oneofs=["request"])
message("ResponseOp", [("response_range", 1, MSG, OPT, "RangeResponse", 0),
                       ("response_put", 2, MSG, OPT, "PutResponse", 0),
                       ("response_delete_range", 3, MSG, OPT, "DeleteRangeResponse", 0)],
        oneofs=["response"])
message("Compare", [("result", 1, I32), ("target", 2, I32), ("key", 3, BYTES),
                    ("version", 4, I64, OPT, None, 0), ("create_revision", 5, I64, OPT, None, 0),
                    ("mod_revision", 6, I64, OPT, None, 0), ("value", 7, BYTES, OPT, None, 0),
                    ("lease", 8, I64, OPT, None, 0), ("range_end", 64, BYTES)],
        oneofs=["target_union"])
message("TxnRequest", [("compare", 1, MSG, REP, "Compare"), ("success", 2, MSG, REP, "RequestOp"),
                       ("failure", 3, MSG, REP, "RequestOp")])
message("TxnResponse", [("header", 1, MSG, OPT, "ResponseHeader"), ("succeeded", 2, BOOL),
                        ("responses", 3, MSG, REP, "ResponseOp")])
message("CompactionRequest", [("revision", 1, I64), ("physical", 2, BOOL)])
message("CompactionResponse", [("header", 1, MSG, OPT, "ResponseHeader")])

pool = descriptor_pool.DescriptorPool()
pool.Add(fdp)
M = {d.name: message_factory.GetMessageClass(d)
     for d in pool.FindFileByName("netget_etcd_subset.proto").message_types_by_name.values()}

port = int(sys.argv[1])
channel = grpc.insecure_channel(f"127.0.0.1:{port}")


def rpc(method, request_type, response_type, **fields):
    call = channel.unary_unary(
        f"/etcdserverpb.KV/{method}",
        request_serializer=lambda m: m.SerializeToString(),
        response_deserializer=M[response_type].FromString,
    )
    return call(M[request_type](**fields), timeout=30)


def check(step, cond, detail):
    if not cond:
        print(f"FAIL {step}: {detail}", flush=True)
        sys.exit(1)
    print(f"ok {step}", flush=True)


# --- Put, and Put asking for the previous pair ------------------------------------------------
put = rpc("Put", "PutRequest", "PutResponse", key=b"/config/database", value=b"localhost:5432")
check("put", put.header.revision >= 1, f"revision {put.header.revision}")
put2 = rpc("Put", "PutRequest", "PutResponse", key=b"/config/database", value=b"db2:5432",
           prev_kv=True)
check("put prev_kv", put2.prev_kv.value == b"localhost:5432",
      f"prev_kv {put2.prev_kv!r}")
check("put revision rises", put2.header.revision > put.header.revision,
      f"{put.header.revision} then {put2.header.revision}")

# --- Range: single key; prefix with a limit the server must enforce; keys only ----------------
got = rpc("Range", "RangeRequest", "RangeResponse", key=b"/config/database")
check("range", [(kv.key, kv.value) for kv in got.kvs] == [(b"/config/database", b"db2:5432")]
      and got.count == 1, f"{got!r}")
limited = rpc("Range", "RangeRequest", "RangeResponse", key=b"/config/", range_end=b"/config0",
              limit=2)
check("range limit", len(limited.kvs) == 2 and limited.more and limited.count == 3,
      f"kvs {len(limited.kvs)} more {limited.more} count {limited.count}")
keys = rpc("Range", "RangeRequest", "RangeResponse", key=b"/config/", range_end=b"/config0",
           keys_only=True)
check("range keys_only", len(keys.kvs) == 3 and all(kv.value == b"" for kv in keys.kvs)
      and keys.kvs[0].key == b"/config/a", f"{keys!r}")

# --- an error the handler chose: NOT_FOUND, Trailers-Only -------------------------------------
try:
    rpc("Range", "RangeRequest", "RangeResponse", key=b"/missing")
    check("range error", False, "a Range the handler answered with etcd_error succeeded")
except grpc.RpcError as e:
    check("range error", e.code() == grpc.StatusCode.NOT_FOUND,
          f"{e.code()} {e.details()}")

# --- DeleteRange with the deleted pairs -------------------------------------------------------
deleted = rpc("DeleteRange", "DeleteRangeRequest", "DeleteRangeResponse", key=b"/config/database",
              prev_kv=True)
check("delete", deleted.deleted == 1 and deleted.prev_kvs[0].value == b"db2:5432",
      f"{deleted!r}")

# --- Txn: the lock pattern. Taken, then not taken, each with its branch's responses -----------
Compare, RequestOp = M["Compare"], M["RequestOp"]
taken = rpc("Txn", "TxnRequest", "TxnResponse",
            compare=[Compare(result=0, target=1, key=b"/lock/a", create_revision=0)],
            success=[RequestOp(request_put=M["PutRequest"](key=b"/lock/a", value=b"me"))],
            failure=[RequestOp(request_range=M["RangeRequest"](key=b"/lock/a"))])
check("txn taken", taken.succeeded and len(taken.responses) == 1
      and taken.responses[0].WhichOneof("response") == "response_put", f"{taken!r}")
held = rpc("Txn", "TxnRequest", "TxnResponse",
           compare=[Compare(result=0, target=1, key=b"/lock/b", create_revision=0)],
           success=[RequestOp(request_put=M["PutRequest"](key=b"/lock/b", value=b"me"))],
           failure=[RequestOp(request_range=M["RangeRequest"](key=b"/lock/b"))])
check("txn not taken", not held.succeeded and len(held.responses) == 1
      and held.responses[0].response_range.kvs[0].value == b"owner-1", f"{held!r}")

# --- Compact: the current revision, then the same again, then the future --------------------
rev = rpc("Range", "RangeRequest", "RangeResponse", key=b"/config/database").header.revision
rpc("Compact", "CompactionRequest", "CompactionResponse", revision=rev)
check("compact", True, "")
for label, revision in [("compact again", rev), ("compact future", rev + 1000)]:
    try:
        rpc("Compact", "CompactionRequest", "CompactionResponse", revision=revision)
        check(label, False, f"revision {revision} was compacted")
    except grpc.RpcError as e:
        check(label, e.code() == grpc.StatusCode.OUT_OF_RANGE, f"{e.code()} {e.details()}")

print("ALL OK", flush=True)
