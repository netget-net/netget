// Independent quic-go RFC 9221 DATAGRAM peer for the raw QUIC tests.
//
// quic-go (Go, no shared code with Quinn or aioquic) owns TLS, QUIC and the
// DATAGRAM frame. The command line matches tests/helpers/quic_datagram_peer.py:
//
//	server -port 0 -cert C -key K   prints {"ready":true,"port":N}, then one
//	                                {"datagram":hex} line per datagram received,
//	                                answering each with "echo:" + payload
//	client -port N -ca C -send '["hex",...]' -expect K
//	                                sends each datagram and prints
//	                                {"received":[hex,...]} once K arrived
//
// Build: go build -o <dir>/quic-go-peer ./tests/helpers/quic_go_peer
// and export NETGET_QUIC_GO_PEER=<dir>/quic-go-peer.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

const alpn = "netget-quic"

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func emit(v any) {
	b, _ := json.Marshal(v)
	fmt.Println(string(b))
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: quic-go-peer server|client [flags]")
	}
	mode := os.Args[1]
	flags := flag.NewFlagSet(mode, flag.ExitOnError)
	port := flags.Int("port", 0, "UDP port")
	cert := flags.String("cert", "", "server certificate PEM")
	key := flags.String("key", "", "server key PEM")
	ca := flags.String("ca", "", "certificate to trust")
	send := flags.String("send", "[]", "JSON list of hex datagrams to send")
	expect := flags.Int("expect", 0, "datagrams to wait for")
	_ = flags.Parse(os.Args[2:])
	conf := &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 15 * time.Second}

	switch mode {
	case "server":
		pair, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			fail("certificate: %v", err)
		}
		tlsConf := &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{alpn}}
		listener, err := quic.ListenAddr(fmt.Sprintf("127.0.0.1:%d", *port), tlsConf, conf)
		if err != nil {
			fail("listen: %v", err)
		}
		emit(map[string]any{"ready": true, "port": listener.Addr().(*net.UDPAddr).Port})
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				fail("accept: %v", err)
			}
			go func() {
				for {
					data, err := conn.ReceiveDatagram(context.Background())
					if err != nil {
						return
					}
					emit(map[string]string{"datagram": hex.EncodeToString(data)})
					_ = conn.SendDatagram(append([]byte("echo:"), data...))
				}
			}()
		}
	case "client":
		pem, err := os.ReadFile(*ca)
		if err != nil {
			fail("ca: %v", err)
		}
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(pem)
		tlsConf := &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{alpn}}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", *port), tlsConf, conf)
		if err != nil {
			fail("dial: %v", err)
		}
		if !conn.ConnectionState().SupportsDatagrams {
			fail("the server did not negotiate RFC 9221 datagrams")
		}
		var payloads []string
		if err := json.Unmarshal([]byte(*send), &payloads); err != nil {
			fail("send: %v", err)
		}
		for _, p := range payloads {
			b, err := hex.DecodeString(p)
			if err != nil {
				fail("hex: %v", err)
			}
			if err := conn.SendDatagram(b); err != nil {
				fail("send datagram: %v", err)
			}
		}
		received := []string{}
		for len(received) < *expect {
			data, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				emit(map[string]any{"timeout": true, "received": received})
				os.Exit(1)
			}
			received = append(received, hex.EncodeToString(data))
		}
		emit(map[string]any{"received": received})
		_ = conn.CloseWithError(0, "done")
	default:
		fail("unknown mode %q", mode)
	}
}
