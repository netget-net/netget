// The `notify` mode: Basic Notification through use-go/onvif's own event.Subscribe. The program
// runs the consumer itself — a net/http server on a loopback port it binds — subscribes it with
// the library's request type (CallMethod to the Events XAddr), prints {"step": "subscribed"},
// and collects every Notify the device POSTs until one carries the DigitalInput the test raises
// (or 30 s pass). Then Renew and Unsubscribe at the subscription's address through the library's
// SOAP builder (CallMethod only knows service XAddrs), a Subscribe naming a consumer outside the
// device's allowlist, and one naming an https consumer.
package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/use-go/onvif"
	"github.com/use-go/onvif/event"
)

type subscribeEnv struct {
	Body struct {
		SubscribeResponse struct {
			SubscriptionReference struct {
				Address string
			}
			CurrentTime     string
			TerminationTime string
		}
	}
}

type notifyEnv struct {
	Header struct {
		Action string
		To     string
	}
	Body struct {
		Notify struct {
			NotificationMessage []struct {
				SubscriptionReference struct{ Address string }
				Topic                 event.Topic
				ProducerReference     struct{ Address string }
				Message               struct {
					Message struct {
						UtcTime           string `xml:"UtcTime,attr"`
						PropertyOperation string `xml:"PropertyOperation,attr"`
						Source            struct{ SimpleItem []item }
						Data              struct{ SimpleItem []item }
					}
				}
			}
		}
	}
}

func itemMap(list []item) map[string]string {
	out := map[string]string{}
	for _, i := range list {
		out[i.Name] = i.Value
	}
	return out
}

func runNotify(dev *onvif.Device, user, password string) {
	out := map[string]interface{}{}
	defer func() {
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
	}()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		out["listen_error"] = err.Error()
		return
	}
	defer ln.Close()
	var mu sync.Mutex
	posts := []map[string]interface{}{}
	arrived := make(chan struct{}, 64)
	mux := http.NewServeMux()
	mux.HandleFunc("/use-go-consumer", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var n notifyEnv
		parsed := xml.Unmarshal(body, &n)
		messages := []map[string]interface{}{}
		for _, m := range n.Body.Notify.NotificationMessage {
			messages = append(messages, map[string]interface{}{
				"topic":              strings.TrimSpace(string(m.Topic.TopicKinds)),
				"subscription":       m.SubscriptionReference.Address,
				"producer":           m.ProducerReference.Address,
				"utc_time":           m.Message.Message.UtcTime,
				"property_operation": m.Message.Message.PropertyOperation,
				"source":             itemMap(m.Message.Message.Source.SimpleItem),
				"data":               itemMap(m.Message.Message.Data.SimpleItem),
			})
		}
		mu.Lock()
		posts = append(posts, map[string]interface{}{"method": r.Method, "path": r.URL.Path,
			"content_type": r.Header.Get("Content-Type"), "action": strings.TrimSpace(n.Header.Action),
			"to": strings.TrimSpace(n.Header.To), "parse_error": fmt.Sprint(parsed), "messages": messages})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		select {
		case arrived <- struct{}{}:
		default:
		}
	})
	go http.Serve(ln, mux)
	consumer := "http://" + ln.Addr().String() + "/use-go-consumer"
	out["consumer"] = consumer

	var sub subscribeEnv
	out["subscribe"] = result(cm(dev, event.Subscribe{
		ConsumerReference:      event.EndpointReferenceType{Address: event.AttributedURIType(consumer)},
		InitialTerminationTime: event.TerminationTime("PT120S"),
	}), &sub)
	address := sub.Body.SubscribeResponse.SubscriptionReference.Address
	out["address"] = address
	out["termination_time"] = sub.Body.SubscribeResponse.TerminationTime
	fmt.Println(`{"step": "subscribed"}`)

	deadline := time.After(30 * time.Second)
wait:
	for {
		select {
		case <-arrived:
			mu.Lock()
			done := false
			for _, p := range posts {
				for _, m := range p["messages"].([]map[string]interface{}) {
					if strings.HasSuffix(m["topic"].(string), "DigitalInput") {
						done = true
					}
				}
			}
			mu.Unlock()
			if done {
				break wait
			}
		case <-deadline:
			break wait
		}
	}
	mu.Lock()
	out["notifies"] = posts
	mu.Unlock()

	out["renew"] = result(sa(address, user, password, event.Renew{
		TerminationTime: event.AbsoluteOrRelativeTimeType{Duration: "PT300S"}}), nil)
	out["unsubscribe"] = result(sa(address, user, password, event.Unsubscribe{}), nil)
	out["renew_after_unsubscribe"] = result(sa(address, user, password, event.Renew{
		TerminationTime: event.AbsoluteOrRelativeTimeType{Duration: "PT300S"}}), nil)
	out["subscribe_outside_allowlist"] = result(cm(dev, event.Subscribe{
		ConsumerReference:      event.EndpointReferenceType{Address: "http://192.0.2.1:9/use-go-consumer"},
		InitialTerminationTime: event.TerminationTime("PT120S"),
	}), nil)
	out["subscribe_https"] = result(cm(dev, event.Subscribe{
		ConsumerReference:      event.EndpointReferenceType{Address: event.AttributedURIType("https://" + ln.Addr().String() + "/use-go-consumer")},
		InitialTerminationTime: event.TerminationTime("PT120S"),
	}), nil)
}
