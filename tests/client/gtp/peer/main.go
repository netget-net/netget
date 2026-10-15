// gtp-peer: an independent GTP peer built on wmnsk/go-gtp, for NetGet's GTP client tests.
// Every message it reads is parsed by go-gtp and every message it sends is go-gtp's encoding.
// It prints one JSON object per line: what it decoded ("got", with the raw octets NetGet sent
// in "raw"), and what it sent back ("sent", with its own octets).
//
//	gtp-peer pgw    be a PGW on S5/S8: GTPv2-C on one UDP socket, GTP-U on another
//
// The PGW drops the first copy of a Create Session Request, so the client's retransmission
// is exercised against a real peer. It answers Create Session, Modify Bearer, Delete Session
// and Echo; Echo-probes the client on both planes; answers an ICMP echo request tunnelled to
// it with the echo reply a host would send, on the TEID the client advertised; and sends one
// G-PDU to a TEID the client never gave out.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"

	v1ie "github.com/wmnsk/go-gtp/gtpv1/ie"
	v1msg "github.com/wmnsk/go-gtp/gtpv1/message"
	"github.com/wmnsk/go-gtp/gtpv2/ie"
	"github.com/wmnsk/go-gtp/gtpv2/message"
)

var outMu sync.Mutex

func out(v map[string]any) {
	b, _ := json.Marshal(v)
	outMu.Lock()
	fmt.Println(string(b))
	outMu.Unlock()
}

func fail(err error) {
	out(map[string]any{"error": err.Error()})
	os.Exit(1)
}

const (
	pgwControlTEID = 0x0A0B0C01
	pgwDataTEID    = 0x0A0B0C02
	ueAddress      = "10.45.0.7"
	dnsServer      = "10.45.0.53"
	unknownTEID    = 0x00DEAD00
)

type state struct {
	mu         sync.Mutex
	sgwCTEID   uint32
	sgwUTEID   uint32
	creates    int
	clientUser net.Addr
}

func marshal2(m message.Message) []byte {
	b := make([]byte, m.MarshalLen())
	if err := m.MarshalTo(b); err != nil {
		fail(err)
	}
	return b
}

func marshal1(m v1msg.Message) []byte {
	b := make([]byte, m.MarshalLen())
	if err := m.MarshalTo(b); err != nil {
		fail(err)
	}
	return b
}

func fteid(i *ie.IE) map[string]any {
	if i == nil {
		return nil
	}
	f := map[string]any{"instance": i.Instance()}
	if t, err := i.InterfaceType(); err == nil {
		f["interface_type"] = t
	}
	if t, err := i.TEID(); err == nil {
		f["teid"] = t
	}
	if ip, err := i.IPv4(); err == nil {
		f["ipv4"] = ip.String()
	}
	return f
}

func str(f func() (string, error)) any {
	v, err := f()
	if err != nil {
		return nil
	}
	return v
}

func u8(f func() (uint8, error)) any {
	v, err := f()
	if err != nil {
		return nil
	}
	return v
}

func bearer(bc *ie.IE) map[string]any {
	b := map[string]any{}
	fteids := []map[string]any{}
	for _, c := range bc.ChildIEs {
		switch c.Type {
		case ie.EPSBearerID:
			b["ebi"] = u8(c.EPSBearerID)
		case ie.FullyQualifiedTEID:
			fteids = append(fteids, fteid(c))
		case ie.BearerQoS:
			q, err := c.BearerQoS()
			if err == nil {
				pl, _ := c.PriorityLevel()
				b["qos"] = map[string]any{"qci": q.QCI, "priority_level": pl,
					"pci": q.ARP >> 6 & 1, "pvi": q.ARP & 1,
					"mbr_ul": q.MaximumBitRateForUplink, "mbr_dl": q.MaximumBitRateForDownlink,
					"gbr_ul": q.GuaranteedBitRateForUplink, "gbr_dl": q.GuaranteedBitRateForDownlink}
			}
		}
	}
	b["fteids"] = fteids
	return b
}

func control(c *net.UDPConn, s *state) {
	buf := make([]byte, 65535)
	for {
		n, raddr, err := c.ReadFrom(buf)
		if err != nil {
			fail(err)
		}
		raw := append([]byte(nil), buf[:n]...)
		msg, err := message.Parse(raw)
		if err != nil {
			out(map[string]any{"got": "unparseable", "plane": "control", "error": err.Error(), "raw": hex.EncodeToString(raw)})
			continue
		}
		send := func(m message.Message) {
			b := marshal2(m)
			if _, err := c.WriteTo(b, raddr); err != nil {
				fail(err)
			}
			out(map[string]any{"sent": m.MessageTypeName(), "plane": "control", "raw": hex.EncodeToString(b)})
		}
		got := map[string]any{"plane": "control", "seq": msg.Sequence(), "raw": hex.EncodeToString(raw)}
		switch m := msg.(type) {
		case *message.EchoRequest:
			got["got"] = "echo_request"
			if m.Recovery != nil {
				got["recovery"] = u8(m.Recovery.Recovery)
			}
			out(got)
			send(message.NewEchoResponse(m.Sequence(), ie.NewRecovery(5)))
		case *message.EchoResponse:
			got["got"] = "echo_response"
			if m.Recovery != nil {
				got["recovery"] = u8(m.Recovery.Recovery)
			}
			out(got)
		case *message.CreateSessionRequest:
			s.mu.Lock()
			s.creates++
			copyNo := s.creates
			s.mu.Unlock()
			got["got"] = "create_session"
			got["copy"] = copyNo
			got["header_teid"] = m.TEID()
			if m.IMSI != nil {
				got["imsi"] = str(m.IMSI.IMSI)
			}
			if m.MSISDN != nil {
				got["msisdn"] = str(m.MSISDN.MSISDN)
			}
			if m.MEI != nil {
				got["mei"] = str(m.MEI.MobileEquipmentIdentity)
			}
			if m.ServingNetwork != nil {
				got["mcc"] = str(m.ServingNetwork.MCC)
				got["mnc"] = str(m.ServingNetwork.MNC)
			}
			if m.RATType != nil {
				got["rat_type"] = u8(m.RATType.RATType)
			}
			if m.APN != nil {
				got["apn"] = str(m.APN.AccessPointName)
			}
			if m.SelectionMode != nil {
				got["selection_mode"] = u8(m.SelectionMode.SelectionMode)
			}
			if m.PDNType != nil {
				got["pdn_type"] = u8(m.PDNType.PDNType)
			}
			if m.PAA != nil {
				got["paa"] = hex.EncodeToString(m.PAA.Payload)
			}
			if m.AMBR != nil {
				ul, _ := m.AMBR.AggregateMaximumBitRateUp()
				dl, _ := m.AMBR.AggregateMaximumBitRateDown()
				got["ambr"] = []uint32{ul, dl}
			}
			if m.PCO != nil {
				if p, err := m.PCO.ProtocolConfigurationOptions(); err == nil {
					ids := []uint16{}
					for _, c := range p.ProtocolOrContainers {
						ids = append(ids, c.ID)
					}
					got["pco_containers"] = ids
				}
			}
			if m.Recovery != nil {
				got["recovery"] = u8(m.Recovery.Recovery)
			}
			got["sender_fteid"] = fteid(m.SenderFTEIDC)
			if len(m.BearerContextsToBeCreated) > 0 {
				got["bearer"] = bearer(m.BearerContextsToBeCreated[0])
			}
			if copyNo == 1 {
				got["dropped"] = true
				out(got)
				continue
			}
			out(got)
			if m.SenderFTEIDC == nil || len(m.BearerContextsToBeCreated) == 0 {
				send(message.NewCreateSessionResponse(0, m.Sequence(), ie.NewCause(70, 0, 0, 0, nil)))
				continue
			}
			sgwC, _ := m.SenderFTEIDC.TEID()
			var sgwU uint32
			var ebi uint8 = 5
			for _, ch := range m.BearerContextsToBeCreated[0].ChildIEs {
				switch ch.Type {
				case ie.FullyQualifiedTEID:
					sgwU, _ = ch.TEID()
				case ie.EPSBearerID:
					ebi, _ = ch.EPSBearerID()
				}
			}
			s.mu.Lock()
			s.sgwCTEID, s.sgwUTEID = sgwC, sgwU
			s.mu.Unlock()
			local := c.LocalAddr().(*net.UDPAddr).IP.String()
			send(message.NewCreateSessionResponse(sgwC, m.Sequence(),
				ie.NewCause(16, 0, 0, 0, nil),
				ie.NewFullyQualifiedTEID(7, pgwControlTEID, local, "").WithInstance(0),
				ie.NewPDNAddressAllocation(ueAddress),
				ie.NewAPNRestriction(0),
				ie.NewAggregateMaximumBitRate(50000, 150000),
				ie.NewProtocolConfigurationOptions(0, ie.NewPCOContainer(0x000D, net.ParseIP(dnsServer).To4())),
				ie.NewBearerContext(
					ie.NewCause(16, 0, 0, 0, nil),
					ie.NewEPSBearerID(ebi),
					ie.NewFullyQualifiedTEID(5, pgwDataTEID, local, "").WithInstance(2),
					ie.NewChargingID(77),
				),
				ie.NewRecovery(5),
			))
			// Probe the client's control plane: it must answer in Rust.
			send(message.NewEchoRequest(0x00ABCD, ie.NewRecovery(5)))
		case *message.ModifyBearerRequest:
			got["got"] = "modify_bearer"
			got["header_teid"] = m.TEID()
			if len(m.BearerContextsToBeModified) > 0 {
				got["bearer"] = bearer(m.BearerContextsToBeModified[0])
			}
			out(got)
			s.mu.Lock()
			sgwC := s.sgwCTEID
			s.mu.Unlock()
			send(message.NewModifyBearerResponse(sgwC, m.Sequence(),
				ie.NewCause(16, 0, 0, 0, nil),
				ie.NewBearerContext(ie.NewCause(16, 0, 0, 0, nil), ie.NewEPSBearerID(5)),
			))
		case *message.DeleteSessionRequest:
			got["got"] = "delete_session"
			got["header_teid"] = m.TEID()
			if m.LinkedEBI != nil {
				got["linked_ebi"] = u8(m.LinkedEBI.EPSBearerID)
			}
			out(got)
			s.mu.Lock()
			sgwC := s.sgwCTEID
			s.mu.Unlock()
			send(message.NewDeleteSessionResponse(sgwC, m.Sequence(), ie.NewCause(16, 0, 0, 0, nil)))
		default:
			got["got"] = msg.MessageTypeName()
			out(got)
		}
	}
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// inner reads an IPv4 packet the way a host would, independently of NetGet's code. It returns
// the packet when it is an ICMP echo request worth answering.
func inner(p []byte) (map[string]any, []byte) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return map[string]any{"ipv4": false}, nil
	}
	ihl := int(p[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(p[2:4]))
	if total > len(p) || ihl > total {
		return map[string]any{"ipv4": true, "length_ok": false}, nil
	}
	f := map[string]any{"ipv4": true, "length_ok": total == len(p),
		"src": net.IP(p[12:16]).String(), "dst": net.IP(p[16:20]).String(),
		"protocol": p[9], "ttl": p[8], "ip_checksum_ok": checksum(p[:ihl]) == 0}
	t := p[ihl:total]
	if p[9] == 1 && len(t) >= 8 {
		f["icmp_type"] = t[0]
		f["icmp_id"] = binary.BigEndian.Uint16(t[4:6])
		f["icmp_seq"] = binary.BigEndian.Uint16(t[6:8])
		f["icmp_checksum_ok"] = checksum(t) == 0
		f["payload"] = string(t[8:])
		if t[0] == 8 {
			return f, p[:total]
		}
		return f, nil
	}
	if p[9] == 17 && len(t) >= 8 {
		f["src_port"] = binary.BigEndian.Uint16(t[0:2])
		f["dst_port"] = binary.BigEndian.Uint16(t[2:4])
		pseudo := append(append([]byte{}, p[12:20]...), 0, 17, t[4], t[5])
		f["udp_checksum_ok"] = checksum(append(pseudo, t...)) == 0
		f["payload"] = string(t[8:])
	}
	return f, nil
}

// reply turns an ICMP echo request into the echo reply a host would send.
func reply(req []byte) []byte {
	ihl := int(req[0]&0x0f) * 4
	r := append([]byte(nil), req...)
	copy(r[12:16], req[16:20])
	copy(r[16:20], req[12:16])
	r[8] = 64
	r[10], r[11] = 0, 0
	binary.BigEndian.PutUint16(r[10:12], checksum(r[:ihl]))
	t := r[ihl:]
	t[0] = 0
	t[2], t[3] = 0, 0
	binary.BigEndian.PutUint16(t[2:4], checksum(t))
	return r
}

func user(u *net.UDPConn, s *state) {
	buf := make([]byte, 65535)
	for {
		n, raddr, err := u.ReadFrom(buf)
		if err != nil {
			fail(err)
		}
		raw := append([]byte(nil), buf[:n]...)
		msg, err := v1msg.Parse(raw)
		if err != nil {
			out(map[string]any{"got": "unparseable", "plane": "user", "error": err.Error(), "raw": hex.EncodeToString(raw)})
			continue
		}
		send := func(m v1msg.Message, what string) {
			b := marshal1(m)
			if _, err := u.WriteTo(b, raddr); err != nil {
				fail(err)
			}
			out(map[string]any{"sent": what, "plane": "user", "raw": hex.EncodeToString(b)})
		}
		got := map[string]any{"plane": "user", "teid": msg.TEID(), "raw": hex.EncodeToString(raw)}
		switch m := msg.(type) {
		case *v1msg.TPDU:
			got["got"] = "gpdu"
			got["seq"] = m.Sequence()
			f, echo := inner(m.Payload)
			got["inner"] = f
			out(got)
			s.mu.Lock()
			first := s.clientUser == nil
			s.clientUser = raddr
			sgwU := s.sgwUTEID
			s.mu.Unlock()
			if echo != nil && first {
				send(v1msg.NewTPDU(sgwU, reply(echo)), "gpdu_echo_reply")
				send(v1msg.NewTPDU(unknownTEID, reply(echo)), "gpdu_unknown_teid")
				// Probe the client's user plane: it must answer in Rust.
				send(v1msg.NewEchoRequest(0x0BEE), "user_echo_request")
			}
		case *v1msg.EchoRequest:
			got["got"] = "user_echo_request"
			got["seq"] = m.Sequence()
			out(got)
			send(v1msg.NewEchoResponse(m.Sequence(), v1ie.NewRecovery(5)), "user_echo_response")
		case *v1msg.EchoResponse:
			got["got"] = "user_echo_response"
			got["seq"] = m.Sequence()
			if m.Recovery != nil {
				got["recovery"] = u8(m.Recovery.Recovery)
			}
			out(got)
		case *v1msg.ErrorIndication:
			got["got"] = "error_indication"
			if m.TEIDDataI != nil {
				t, _ := m.TEIDDataI.TEID()
				got["teid_data_i"] = t
			}
			if m.GTPUPeerAddress != nil {
				got["peer_address"] = str(m.GTPUPeerAddress.IPAddress)
			}
			out(got)
		case *v1msg.EndMarker:
			got["got"] = "end_marker"
			out(got)
		default:
			got["got"] = msg.MessageTypeName()
			out(got)
		}
	}
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "pgw" {
		fail(fmt.Errorf("usage: gtp-peer pgw"))
	}
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		fail(err)
	}
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		fail(err)
	}
	out(map[string]any{"listening": c.LocalAddr().String(), "user": u.LocalAddr().String()})
	s := &state{}
	go user(u, s)
	control(c, s)
}
