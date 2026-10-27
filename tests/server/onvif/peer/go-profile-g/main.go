// Recording, Search and Replay (ONVIF Profile G) through github.com/videonext/onvif, a Go client
// generated from ONVIF's WSDLs with gowsdl: its own request types, its own SOAP 1.2 envelope and
// encoding/xml, nothing shared with zeep.
//
// Requests go out through the library's ports (devicemgmt, recording, search, replay) and
// answers are read with the library's own response types — except two the library cannot decode
// from any device: GetEventSearchResults (its FindEventResult's Event tag conflicts with its own
// type's XMLName, so encoding/xml refuses the type) and Replay's GetServiceCapabilities (it types
// SessionTimeoutRange, a list of floats, as one float). Those two are captured as they arrived,
// through the library's WithHTTPClient hook, and read with the small structs below, as the use-go
// peer does for that library's untagged fields; the library's error is reported beside them.
//
// The library computes the WS-Security PasswordDigest over the nonce's base64 text instead of
// its bytes, so a device that checks digests refuses it. With a username and password the
// program makes one signed GetRecordings and reports the fault; without, it runs the whole
// sequence unsigned.
//
// Prints one JSON object. Usage: onvif-go-profile-g host:port [username password]
package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/videonext/onvif/profiles/devicemgmt"
	"github.com/videonext/onvif/profiles/recording"
	"github.com/videonext/onvif/profiles/replay"
	"github.com/videonext/onvif/profiles/search"
	"github.com/videonext/onvif/soap"
)

// tee is the library's HTTP client, keeping the last answer's body.
type tee struct {
	mu   sync.Mutex
	last []byte
	c    http.Client
}

func (t *tee) Do(req *http.Request) (*http.Response, error) {
	resp, err := t.c.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.last = body
	t.mu.Unlock()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

func (t *tee) body() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.last
}

type subcode struct {
	Value   string
	Subcode *subcode
}

type faultEnv struct {
	Body struct {
		Fault *struct {
			Code struct {
				Value   string
				Subcode *subcode
			}
		}
	}
}

// faultText is a fault's code and every subcode, e.g. env:Sender/ter:InvalidArgVal/ter:NoRecording.
func faultText(body []byte) string {
	var f faultEnv
	if xml.Unmarshal(body, &f) != nil || f.Body.Fault == nil {
		return ""
	}
	out := f.Body.Fault.Code.Value
	for s := f.Body.Fault.Code.Subcode; s != nil; s = s.Subcode {
		out += "/" + s.Value
	}
	return out
}

type info struct {
	RecordingToken string
	Source         struct{ SourceId, Name string }
	Content        string
	Track          []struct{ TrackToken, TrackType, DataFrom, DataTo string }
	RecordingStatus string
}

type recordingResultsEnv struct {
	Body struct {
		GetRecordingSearchResultsResponse struct {
			ResultList struct {
				SearchState          string
				RecordingInformation []info
			}
		}
	}
}

type item struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:"Value,attr"`
}

type eventResultsEnv struct {
	Body struct {
		GetEventSearchResultsResponse struct {
			ResultList struct {
				SearchState string
				Result      []struct {
					RecordingToken  string
					TrackToken      string
					Time            string
					StartStateEvent bool
					Event           struct {
						Topic   string
						Message struct {
							Message struct {
								UtcTime string `xml:"UtcTime,attr"`
								Source  struct{ SimpleItem []item }
								Data    struct{ SimpleItem []item }
							}
						}
					}
				}
			}
		}
	}
}

type capsEnv struct {
	Body struct {
		GetServiceCapabilitiesResponse struct {
			Capabilities struct {
				Attrs []xml.Attr `xml:",any,attr"`
			}
		}
	}
}

func items(list []item) map[string]string {
	out := map[string]string{}
	for _, i := range list {
		out[i.Name] = i.Value
	}
	return out
}

func main() {
	if len(os.Args) != 2 && len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: onvif-go-profile-g host:port [username password]")
		os.Exit(2)
	}
	base := "http://" + os.Args[1]
	out := map[string]interface{}{}
	emit := func() {
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
	}
	t := &tee{c: http.Client{Timeout: 30 * time.Second}}
	client := soap.NewClient(soap.WithHTTPClient(t))
	// done records one request: the library's error (a SOAPFault for a fault) and, for a fault,
	// its code and subcodes as they arrived.
	done := func(name string, err error, value interface{}) {
		r := map[string]interface{}{}
		if err != nil {
			r["error"] = err.Error()
			if f := faultText(t.body()); f != "" {
				r["fault"] = f
			}
		} else {
			r["value"] = value
		}
		out[name] = r
	}

	if len(os.Args) == 4 {
		client.AddHeader(soap.NewWSSSecurityHeader(os.Args[2], os.Args[3], time.Now().UTC()))
		rec := recording.NewRecordingPort(client, base+"/onvif/recording_service")
		_, err := rec.GetRecordings(&recording.GetRecordings{})
		done("signed_get_recordings", err, nil)
		emit()
		return
	}

	// The services, from the library's GetServices.
	xaddrs := map[string]string{}
	{
		dm := devicemgmt.NewDevice(client, base+"/onvif/device_service")
		services, err := dm.GetServices(&devicemgmt.GetServices{IncludeCapability: false})
		if err != nil {
			out["get_services"] = err.Error()
			emit()
			return
		}
		for _, svc := range services.Service {
			xaddrs[string(svc.Namespace)] = string(svc.XAddr)
		}
	}
	out["xaddrs"] = xaddrs
	rec := recording.NewRecordingPort(client, xaddrs["http://www.onvif.org/ver10/recording/wsdl"])
	srch := search.NewSearchPort(client, xaddrs["http://www.onvif.org/ver10/search/wsdl"])
	rpl := replay.NewReplayPort(client, xaddrs["http://www.onvif.org/ver10/replay/wsdl"])
	caps := func() map[string]string {
		var c capsEnv
		xml.Unmarshal(t.body(), &c)
		m := map[string]string{}
		for _, a := range c.Body.GetServiceCapabilitiesResponse.Capabilities.Attrs {
			m[a.Name.Local] = a.Value
		}
		return m
	}

	// ---- Recording ----
	_, err := rec.GetServiceCapabilities(&recording.GetServiceCapabilities{})
	done("recording_capabilities", err, caps())
	recs, err := rec.GetRecordings(&recording.GetRecordings{})
	if err == nil {
		list := []map[string]interface{}{}
		for _, r := range recs.RecordingItem {
			tracks := []string{}
			for _, tr := range r.Tracks.Track {
				tracks = append(tracks, string(tr.TrackToken)+":"+string(tr.Configuration.TrackType))
			}
			list = append(list, map[string]interface{}{
				"token": string(r.RecordingToken), "source_id": string(r.Configuration.Source.SourceId),
				"content": string(r.Configuration.Content), "retention": string(r.Configuration.MaximumRetentionTime),
				"tracks": tracks})
		}
		done("recordings", nil, list)
	} else {
		done("recordings", err, nil)
	}
	conf, err := rec.GetRecordingConfiguration(&recording.GetRecordingConfiguration{RecordingToken: "rec_door"})
	if err == nil {
		done("configuration", nil, map[string]string{"source_id": string(conf.RecordingConfiguration.Source.SourceId),
			"name": string(conf.RecordingConfiguration.Source.Name), "content": string(conf.RecordingConfiguration.Content)})
	} else {
		done("configuration", err, nil)
	}
	jobs, err := rec.GetRecordingJobs(&recording.GetRecordingJobs{})
	if err == nil {
		list := []map[string]string{}
		for _, j := range jobs.JobItem {
			list = append(list, map[string]string{"token": string(j.JobToken), "recording": string(j.JobConfiguration.RecordingToken),
				"mode": string(j.JobConfiguration.Mode)})
		}
		done("jobs", nil, list)
	} else {
		done("jobs", err, nil)
	}
	cr := recording.CreateRecording{}
	cr.RecordingConfiguration.Content = "Gate, on motion"
	cr.RecordingConfiguration.MaximumRetentionTime = "P1D"
	cr.RecordingConfiguration.Source = recording.RecordingSourceInformation{SourceId: "gate_cam", Name: "Gate",
		Location: "Gate", Description: "Gate camera", Address: "http://192.0.2.51/onvif/device_service"}
	created, err := rec.CreateRecording(&cr)
	token := recording.RecordingReference("")
	if err == nil {
		token = created.RecordingToken
		done("create", nil, string(token))
	} else {
		done("create", err, nil)
	}
	_, err = rec.DeleteRecording(&recording.DeleteRecording{RecordingToken: token})
	done("delete", err, "ok")
	_, err = rec.DeleteRecording(&recording.DeleteRecording{RecordingToken: "rec_lobby"})
	done("delete_refused", err, "ok")

	// ---- Search ----
	sum, err := srch.GetRecordingSummary(&search.GetRecordingSummary{})
	if err == nil {
		done("summary", nil, map[string]interface{}{"from": sum.Summary.DataFrom, "until": sum.Summary.DataUntil,
			"count": sum.Summary.NumberRecordings})
	} else {
		done("summary", err, nil)
	}
	ri, err := srch.GetRecordingInformation(&search.GetRecordingInformation{RecordingToken: "rec_door"})
	if err == nil {
		tracks := []string{}
		for _, tr := range ri.RecordingInformation.Track {
			tracks = append(tracks, string(tr.TrackToken)+" "+tr.DataFrom+" "+tr.DataTo)
		}
		done("information", nil, map[string]interface{}{"library_token": string(ri.RecordingInformation.RecordingToken),
			"source_id": string(ri.RecordingInformation.Source.SourceId), "earliest": ri.RecordingInformation.EarliestRecording,
			"latest": ri.RecordingInformation.LatestRecording, "status": string(ri.RecordingInformation.RecordingStatus), "tracks": tracks})
	} else {
		done("information", err, nil)
	}
	fr, err := srch.FindRecordings(&search.FindRecordings{MaxMatches: 10, KeepAliveTime: "PT30S"})
	stoken := search.JobToken("")
	if err == nil {
		stoken = fr.SearchToken
	}
	done("find_recordings", err, string(stoken))
	pages := []map[string]interface{}{}
	for i := 0; i < 3; i++ {
		lib, err := srch.GetRecordingSearchResults(&search.GetRecordingSearchResults{SearchToken: stoken, MaxResults: 1})
		if err != nil {
			done("recording_page_error", err, nil)
			break
		}
		var raw recordingResultsEnv
		xml.Unmarshal(t.body(), &raw)
		got := []string{}
		for _, r := range raw.Body.GetRecordingSearchResultsResponse.ResultList.RecordingInformation {
			got = append(got, r.RecordingToken+":"+r.RecordingStatus)
		}
		pages = append(pages, map[string]interface{}{
			"state": raw.Body.GetRecordingSearchResultsResponse.ResultList.SearchState, "recordings": got,
			"library_state": string(lib.ResultList.SearchState), "library_count": len(lib.ResultList.RecordingInformation)})
		if raw.Body.GetRecordingSearchResultsResponse.ResultList.SearchState == "Completed" {
			break
		}
	}
	out["recording_pages"] = pages
	end, err := srch.EndSearch(&search.EndSearch{SearchToken: stoken})
	if err == nil {
		done("end_recordings", nil, end.Endpoint)
	} else {
		done("end_recordings", err, nil)
	}
	fe, err := srch.FindEvents(&search.FindEvents{StartPoint: "2026-10-23T00:00:00Z", EndPoint: "2026-10-24T09:00:00Z",
		MaxMatches: 20, KeepAliveTime: "PT30S"})
	etoken := search.JobToken("")
	if err == nil {
		etoken = fe.SearchToken
	}
	done("find_events", err, string(etoken))
	st, err := srch.GetSearchState(&search.GetSearchState{SearchToken: etoken})
	if err == nil {
		done("search_state", nil, string(st.State))
	} else {
		done("search_state", err, nil)
	}
	// The library's FindEventResult cannot be decoded at all (its Event field's tag conflicts
	// with its own type's XMLName), so the answer is read as it arrived.
	_, err = srch.GetEventSearchResults(&search.GetEventSearchResults{SearchToken: etoken, MaxResults: 10})
	if faultText(t.body()) == "" {
		var raw eventResultsEnv
		xml.Unmarshal(t.body(), &raw)
		results := []map[string]interface{}{}
		for _, r := range raw.Body.GetEventSearchResultsResponse.ResultList.Result {
			results = append(results, map[string]interface{}{"recording": r.RecordingToken, "track": r.TrackToken,
				"time": r.Time, "topic": strings.TrimSpace(r.Event.Topic), "source": items(r.Event.Message.Message.Source.SimpleItem),
				"data": items(r.Event.Message.Message.Data.SimpleItem), "start_state": r.StartStateEvent})
		}
		out["events"] = map[string]interface{}{"value": map[string]interface{}{"state": raw.Body.GetEventSearchResultsResponse.ResultList.SearchState,
			"results": results}, "library_error": fmt.Sprint(err)}
	} else {
		done("events", err, nil)
	}
	end, err = srch.EndSearch(&search.EndSearch{SearchToken: etoken})
	if err == nil {
		done("end_events", nil, end.Endpoint)
	} else {
		done("end_events", err, nil)
	}
	_, err = srch.GetEventSearchResults(&search.GetEventSearchResults{SearchToken: etoken})
	done("ended_events", err, "found")

	// ---- Replay ----
	// The library cannot decode SessionTimeoutRange (a list of floats it types as one float), so
	// the capabilities are read as they arrived; a fault is still a fault.
	_, err = rpl.GetServiceCapabilities(&replay.GetServiceCapabilities{})
	if faultText(t.body()) != "" {
		done("replay_capabilities", err, nil)
	} else {
		out["replay_capabilities"] = map[string]interface{}{"value": caps(), "library_error": fmt.Sprint(err)}
	}
	uri, err := rpl.GetReplayUri(&replay.GetReplayUri{RecordingToken: "rec_door",
		StreamSetup: replay.StreamSetup{Stream: "RTP-Unicast", Transport: replay.Transport{Protocol: "RTSP"}}})
	if err == nil {
		done("replay_uri", nil, string(uri.Uri))
	} else {
		done("replay_uri", err, nil)
	}
	rc, err := rpl.GetReplayConfiguration(&replay.GetReplayConfiguration{})
	if err == nil {
		done("replay_configuration", nil, string(rc.Configuration.SessionTimeout))
	} else {
		done("replay_configuration", err, nil)
	}
	_, err = rpl.GetReplayUri(&replay.GetReplayUri{RecordingToken: "rec_nowhere",
		StreamSetup: replay.StreamSetup{Stream: "RTP-Unicast", Transport: replay.Transport{Protocol: "RTSP"}}})
	done("replay_missing", err, "found")
	emit()
}
