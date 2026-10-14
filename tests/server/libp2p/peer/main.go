// The go-libp2p peer for NetGet's libp2p tests: TCP, Noise and yamux only, so every byte
// NetGet sees or sends is negotiated, encrypted and multiplexed by go-libp2p.
//
//	libp2p-peer dial <multiaddr with /p2p/>   connect to NetGet, identify, ping, talk
//	libp2p-peer probe <multiaddr with /p2p/>  one message, one answer or the error
//	libp2p-peer listen                         wait for NetGet, echo its messages, talk back
//	libp2p-peer raw <multiaddr> <protocol> <hex> [n]
//	                                           write bytes verbatim on one stream, report the
//	                                           answer, then wait for n Bitswap messages
//	libp2p-peer bitswap-liar <good content>    listen; answer wants with the good content's
//	                                           raw block, or a tampered block under the CID
//
// One JSON object per line on stdout.
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/host/basic"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/libp2p/go-msgio"
	ma "github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/encoding/protowire"
)

const chat = protocol.ID("/netget/chat/1.0.0")

func out(v map[string]any) {
	b, _ := json.Marshal(v)
	fmt.Println(string(b))
}

func fail(step string, err error) {
	out(map[string]any{"step": step, "error": err.Error()})
	os.Exit(1)
}

func newHost(listen bool) host.Host {
	opts := []libp2p.Option{
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Muxer(yamux.ID, yamux.DefaultTransport),
		libp2p.UserAgent("netget-test-go-peer"),
		libp2p.DisableRelay(),
		libp2p.Ping(true),
	}
	if listen {
		opts = append(opts, libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	} else {
		opts = append(opts, libp2p.NoListenAddrs)
	}
	h, err := libp2p.New(opts...)
	if err != nil {
		fail("host", err)
	}
	return h
}

// The remote's identify, once go-libp2p has run it.
func identified(h host.Host, c network.Conn) map[string]any {
	id := c.RemotePeer()
	if bh, ok := h.(*basichost.BasicHost); ok {
		select {
		case <-bh.IDService().IdentifyWait(c):
		case <-time.After(10 * time.Second):
		}
	}
	// An inbound connection's notification can precede identify's bookkeeping, so poll too.
	for i := 0; i < 100; i++ {
		if _, err := h.Peerstore().Get(id, "AgentVersion"); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	agent, _ := h.Peerstore().Get(id, "AgentVersion")
	pv, _ := h.Peerstore().Get(id, "ProtocolVersion")
	protos, _ := h.Peerstore().GetProtocols(id)
	names := []string{}
	for _, p := range protos {
		names = append(names, string(p))
	}
	sort.Strings(names)
	addrs := []string{}
	for _, a := range h.Peerstore().Addrs(id) {
		addrs = append(addrs, a.String())
	}
	sort.Strings(addrs)
	return map[string]any{"agent": agent, "protocol_version": pv, "protocols": names, "addrs": addrs}
}

// Send each message on one stream and read the answer to each.
func talk(s network.Stream, msgs ...string) []string {
	w := msgio.NewVarintWriter(s)
	r := msgio.NewVarintReaderSize(s, 1<<20)
	got := []string{}
	for _, m := range msgs {
		if err := w.WriteMsg([]byte(m)); err != nil {
			fail("write", err)
		}
		_ = s.SetReadDeadline(time.Now().Add(20 * time.Second))
		b, err := r.ReadMsg()
		if err != nil {
			fail("read", err)
		}
		got = append(got, string(b))
	}
	return got
}

// Answer NetGet's streams: print what arrives, reply "echo: " + it.
func echo(s network.Stream) {
	r := msgio.NewVarintReaderSize(s, 1<<20)
	w := msgio.NewVarintWriter(s)
	for {
		b, err := r.ReadMsg()
		if err != nil {
			out(map[string]any{"step": "inbound_closed", "error": err.Error()})
			return
		}
		out(map[string]any{"step": "inbound", "protocol": string(s.Protocol()), "body": string(b)})
		if err := w.WriteMsg(append([]byte("echo: "), b...)); err != nil {
			return
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: libp2p-peer dial <multiaddr> | listen")
		os.Exit(2)
	}
	ctx := context.Background()
	switch os.Args[1] {
	case "dial":
		h := newHost(false)
		h.SetStreamHandler(chat, echo)
		addr, err := ma.NewMultiaddr(os.Args[2])
		if err != nil {
			fail("addr", err)
		}
		info, err := peer.AddrInfoFromP2pAddr(addr)
		if err != nil {
			fail("addr", err)
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err := h.Connect(cctx, *info); err != nil {
			fail("connect", err)
		}
		id := identified(h, h.Network().ConnsToPeer(info.ID)[0])
		id["step"] = "identify"
		id["peer_id"] = info.ID.String()
		out(id)
		res := <-ping.Ping(cctx, h, info.ID)
		if res.Error != nil {
			fail("ping", res.Error)
		}
		out(map[string]any{"step": "ping", "ok": true})
		s, err := h.NewStream(cctx, info.ID, chat)
		if err != nil {
			fail("open", err)
		}
		out(map[string]any{"step": "talk", "replies": talk(s, "hello", "how are you?")})
		_ = s.CloseWrite()
		_, err = h.NewStream(cctx, info.ID, "/not/supported/1.0.0")
		out(map[string]any{"step": "unsupported", "refused": err != nil})
		// A message announcing more than NetGet accepts: the stream is reset, not read.
		big, err := h.NewStream(cctx, info.ID, chat)
		if err != nil {
			fail("open", err)
		}
		hdr := binary.AppendUvarint(nil, 2<<20)
		_, _ = big.Write(append(hdr, make([]byte, 100)...))
		_ = big.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, err = big.Read(make([]byte, 1))
		out(map[string]any{"step": "oversize", "error": fmt.Sprint(err)})
		// Stay a moment for any stream NetGet opens to us.
		time.Sleep(3 * time.Second)
		_ = h.Close()
		out(map[string]any{"step": "done"})
	case "probe":
		// One message, one answer (or the error instead of one).
		h := newHost(false)
		addr, _ := ma.NewMultiaddr(os.Args[2])
		info, err := peer.AddrInfoFromP2pAddr(addr)
		if err != nil {
			fail("addr", err)
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err := h.Connect(cctx, *info); err != nil {
			out(map[string]any{"step": "probe", "connect_error": err.Error()})
			return
		}
		s, err := h.NewStream(cctx, info.ID, chat)
		if err != nil {
			fail("open", err)
		}
		_ = msgio.NewVarintWriter(s).WriteMsg([]byte("hello"))
		_ = s.SetReadDeadline(time.Now().Add(15 * time.Second))
		b, err := msgio.NewVarintReaderSize(s, 1<<20).ReadMsg()
		out(map[string]any{"step": "probe", "reply": string(b), "error": fmt.Sprint(err)})
	case "raw":
		raw()
	case "bitswap-liar":
		bitswapLiar()
	case "listen":
		h := newHost(true)
		h.SetStreamHandler(chat, echo)
		h.Network().Notify(&network.NotifyBundle{ConnectedF: func(_ network.Network, c network.Conn) {
			go func() {
				id := identified(h, c)
				id["step"] = "identify"
				id["peer_id"] = c.RemotePeer().String()
				out(id)
				// Then speak first, on a stream of our own.
				sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
				defer cancel()
				s, err := h.NewStream(sctx, c.RemotePeer(), chat)
				if err != nil {
					out(map[string]any{"step": "outbound", "error": err.Error()})
					return
				}
				out(map[string]any{"step": "outbound", "replies": talk(s, "hi from go")})
				_ = s.CloseWrite()
			}()
		}})
		addrs := h.Addrs()
		out(map[string]any{"step": "listening", "addr": fmt.Sprintf("%s/p2p/%s", addrs[0], h.ID())})
		// Run until stdin closes.
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		_ = h.Close()
	}
}

var bitswapIDs = []protocol.ID{"/ipfs/bitswap/1.2.0", "/ipfs/bitswap/1.1.0", "/ipfs/bitswap/1.0.0", "/ipfs/bitswap"}

type field struct {
	num protowire.Number
	v   uint64
	b   []byte
}

// Every varint and bytes field of a protobuf message, in order; stops at the first error.
func parse(b []byte) []field {
	var fs []field
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return fs
		}
		b = b[n:]
		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return fs
			}
			fs = append(fs, field{num: num, v: v})
			b = b[n:]
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return fs
			}
			fs = append(fs, field{num: num, b: v})
			b = b[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return fs
			}
			b = b[n:]
		}
	}
	return fs
}

// A Bitswap message as go-cid reads it: each block's CID computed from its prefix and its
// bytes, and each presence.
func describeBitswap(b []byte) map[string]any {
	blocks := []map[string]any{}
	presences := []map[string]any{}
	for _, f := range parse(b) {
		switch f.num {
		case 3:
			var prefix, data []byte
			for _, x := range parse(f.b) {
				if x.num == 1 {
					prefix = x.b
				} else if x.num == 2 {
					data = x.b
				}
			}
			p, err := cid.PrefixFromBytes(prefix)
			if err != nil {
				blocks = append(blocks, map[string]any{"error": err.Error()})
				continue
			}
			c, err := p.Sum(data)
			if err != nil {
				blocks = append(blocks, map[string]any{"error": err.Error()})
				continue
			}
			blocks = append(blocks, map[string]any{"cid": c.String(), "data": string(data)})
		case 4:
			entry := map[string]any{"type": "have"}
			for _, x := range parse(f.b) {
				if x.num == 1 {
					c, err := cid.Cast(x.b)
					if err == nil {
						entry["cid"] = c.String()
					}
				} else if x.num == 2 && x.v == 1 {
					entry["type"] = "dont_have"
				}
			}
			presences = append(presences, entry)
		}
	}
	return map[string]any{"blocks": blocks, "presences": presences}
}

// Print every Bitswap message that arrives, and count it.
func bitswapIn(got chan<- struct{}) network.StreamHandler {
	return func(s network.Stream) {
		r := msgio.NewVarintReaderSize(s, 4<<20)
		for {
			b, err := r.ReadMsg()
			if err != nil {
				return
			}
			m := describeBitswap(b)
			m["step"] = "bitswap_in"
			m["protocol"] = string(s.Protocol())
			out(m)
			select {
			case got <- struct{}{}:
			default:
			}
		}
	}
}

// Write bytes verbatim on one stream, report what comes back on it, then wait for Bitswap
// messages NetGet sends on streams of its own.
func raw() {
	ctx := context.Background()
	h := newHost(false)
	got := make(chan struct{}, 64)
	for _, id := range bitswapIDs {
		h.SetStreamHandler(id, bitswapIn(got))
	}
	addr, err := ma.NewMultiaddr(os.Args[2])
	if err != nil {
		fail("addr", err)
	}
	info, err := peer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		fail("addr", err)
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := h.Connect(cctx, *info); err != nil {
		fail("connect", err)
	}
	s, err := h.NewStream(cctx, info.ID, protocol.ID(os.Args[3]))
	if err != nil {
		out(map[string]any{"step": "raw", "open_error": err.Error()})
		return
	}
	payload, err := hex.DecodeString(os.Args[4])
	if err != nil {
		fail("hex", err)
	}
	_, _ = s.Write(payload)
	_ = s.CloseWrite()
	_ = s.SetReadDeadline(time.Now().Add(15 * time.Second))
	reply, err := io.ReadAll(s)
	out(map[string]any{"step": "raw", "reply_hex": hex.EncodeToString(reply), "error": fmt.Sprint(err)})
	want := 0
	if len(os.Args) > 5 {
		want, _ = strconv.Atoi(os.Args[5])
	}
	deadline := time.After(20 * time.Second)
	for i := 0; i < want; i++ {
		select {
		case <-got:
		case <-deadline:
			out(map[string]any{"step": "timeout"})
			i = want
		}
	}
	_ = h.Close()
	out(map[string]any{"step": "done"})
}

// Listen, and answer every want with a block: the good content's bytes when they hash to
// the wanted CID, and otherwise "tampered" under the wanted CID's prefix.
func bitswapLiar() {
	ctx := context.Background()
	good := []byte(os.Args[2])
	h := newHost(true)
	handler := func(s network.Stream) {
		r := msgio.NewVarintReaderSize(s, 4<<20)
		for {
			b, err := r.ReadMsg()
			if err != nil {
				return
			}
			var wanted []cid.Cid
			for _, f := range parse(b) {
				if f.num != 1 {
					continue
				}
				for _, e := range parse(f.b) {
					if e.num != 1 {
						continue
					}
					for _, x := range parse(e.b) {
						if x.num == 1 {
							if c, err := cid.Cast(x.b); err == nil {
								wanted = append(wanted, c)
							}
						}
					}
				}
			}
			names := []string{}
			var msg []byte
			for _, c := range wanted {
				names = append(names, c.String())
				data := []byte("tampered")
				if sum, err := c.Prefix().Sum(good); err == nil && sum.Equals(c) {
					data = good
				}
				var blk []byte
				blk = protowire.AppendTag(blk, 1, protowire.BytesType)
				blk = protowire.AppendBytes(blk, c.Prefix().Bytes())
				blk = protowire.AppendTag(blk, 2, protowire.BytesType)
				blk = protowire.AppendBytes(blk, data)
				msg = protowire.AppendTag(msg, 3, protowire.BytesType)
				msg = protowire.AppendBytes(msg, blk)
			}
			out(map[string]any{"step": "wanted", "cids": names})
			if len(wanted) == 0 {
				continue
			}
			sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			ws, err := h.NewStream(sctx, s.Conn().RemotePeer(), bitswapIDs...)
			cancel()
			if err != nil {
				out(map[string]any{"step": "answered", "error": err.Error()})
				continue
			}
			_ = msgio.NewVarintWriter(ws).WriteMsg(msg)
			_ = ws.CloseWrite()
			out(map[string]any{"step": "answered", "blocks": len(wanted)})
		}
	}
	for _, id := range bitswapIDs {
		h.SetStreamHandler(id, handler)
	}
	addrs := h.Addrs()
	out(map[string]any{"step": "listening", "addr": fmt.Sprintf("%s/p2p/%s", addrs[0], h.ID())})
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	_ = h.Close()
}
