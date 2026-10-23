// An ONVIF client built on github.com/use-go/onvif: it connects the way the library does
// (NewDevice, which calls GetCapabilities with a WS-Security digest and keeps the XAddrs), then
// reads device information, scopes, profiles, a stream URI and a snapshot URI through the
// library's own request types and its own encoding/xml response types, and prints one JSON
// object. Usage: onvif-go-client host:port username password
package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"

	"github.com/use-go/onvif"
	"github.com/use-go/onvif/device"
	"github.com/use-go/onvif/media"
	xsdonvif "github.com/use-go/onvif/xsd/onvif"
)

type fault struct {
	Code struct {
		Value   string
		Subcode struct {
			Value string
		}
	}
	Reason struct {
		Text string
	}
}

// call sends one request and decodes the Body into out; a fault is returned as text.
func call(dev *onvif.Device, request interface{}, out interface{}) (int, string, error) {
	resp, err := dev.CallMethod(request)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	var env struct {
		Body struct {
			Fault *fault
			Inner []byte `xml:",innerxml"`
		}
	}
	if err := xml.Unmarshal(body, &env); err != nil {
		return resp.StatusCode, "", err
	}
	if env.Body.Fault != nil {
		return resp.StatusCode, env.Body.Fault.Code.Value + "/" + env.Body.Fault.Code.Subcode.Value, nil
	}
	return resp.StatusCode, "", xml.Unmarshal(body, out)
}

func main() {
	if len(os.Args) != 4 && !(len(os.Args) == 5 && os.Args[4] == "services") {
		fmt.Fprintln(os.Stderr, "usage: onvif-go-client host:port username password [services]")
		os.Exit(2)
	}
	out := map[string]interface{}{}
	emit := func() {
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
	}
	dev, err := onvif.NewDevice(onvif.DeviceParams{Xaddr: os.Args[1], Username: os.Args[2], Password: os.Args[3]})
	if err != nil {
		out["connect_error"] = err.Error()
		emit()
		return
	}
	if len(os.Args) == 5 {
		runServices(dev, os.Args[2], os.Args[3])
	}
	out["endpoints"] = dev.GetServices()

	var info struct {
		Body struct {
			GetDeviceInformationResponse device.GetDeviceInformationResponse
		}
	}
	status, f, err := call(dev, device.GetDeviceInformation{}, &info)
	out["device_information"] = map[string]interface{}{"status": status, "fault": f, "error": fmt.Sprint(err), "value": info.Body.GetDeviceInformationResponse}

	var scopes struct {
		Body struct {
			GetScopesResponse struct {
				Scopes []xsdonvif.Scope
			}
		}
	}
	status, f, err = call(dev, device.GetScopes{}, &scopes)
	items := []string{}
	for _, s := range scopes.Body.GetScopesResponse.Scopes {
		items = append(items, string(s.ScopeItem))
	}
	out["scopes"] = map[string]interface{}{"status": status, "fault": f, "error": fmt.Sprint(err), "items": items}

	var profiles struct {
		Body struct {
			GetProfilesResponse media.GetProfilesResponse
		}
	}
	status, f, err = call(dev, media.GetProfiles{}, &profiles)
	list := []map[string]interface{}{}
	for _, p := range profiles.Body.GetProfilesResponse.Profiles {
		// Only the token and name: the library tags the encoder configuration's fields
		// `xml:"onvif:Encoding"`, which encoding/xml can write but never matches on read.
		list = append(list, map[string]interface{}{
			"token": string(p.Token),
			"name":  string(p.Name),
		})
	}
	out["profiles"] = map[string]interface{}{"status": status, "fault": f, "error": fmt.Sprint(err), "items": list}
	if len(list) == 0 {
		emit()
		return
	}
	token := xsdonvif.ReferenceToken(list[0]["token"].(string))

	var stream struct {
		Body struct {
			GetStreamUriResponse media.GetStreamUriResponse
		}
	}
	status, f, err = call(dev, media.GetStreamUri{
		ProfileToken: token,
		StreamSetup:  xsdonvif.StreamSetup{Stream: "RTP-Unicast", Transport: xsdonvif.Transport{Protocol: "RTSP"}},
	}, &stream)
	out["stream_uri"] = map[string]interface{}{"status": status, "fault": f, "error": fmt.Sprint(err), "uri": string(stream.Body.GetStreamUriResponse.MediaUri.Uri)}

	var snapshot struct {
		Body struct {
			GetSnapshotUriResponse media.GetSnapshotUriResponse
		}
	}
	status, f, err = call(dev, media.GetSnapshotUri{ProfileToken: token}, &snapshot)
	out["snapshot_uri"] = map[string]interface{}{"status": status, "fault": f, "error": fmt.Sprint(err), "uri": string(snapshot.Body.GetSnapshotUriResponse.MediaUri.Uri)}

	// A profile the device does not have: the model refuses it with a fault.
	status, f, err = call(dev, media.GetStreamUri{
		ProfileToken: "nonexistent",
		StreamSetup:  xsdonvif.StreamSetup{Stream: "RTP-Unicast", Transport: xsdonvif.Transport{Protocol: "RTSP"}},
	}, &stream)
	out["missing_profile"] = map[string]interface{}{"status": status, "fault": f, "error": fmt.Sprint(err)}
	emit()
}
