// The `services` mode: PTZ, Events (pull point), Imaging and the Device Set* operations through
// use-go/onvif's own request types. Requests go out through the library: Device.CallMethod for
// every service it can address, and for a pull-point subscription — which CallMethod cannot
// address, it only knows the service XAddrs — the library's own SOAP builder (gosoap, the same
// steps CallMethod takes) posted to the subscription's address with networking.SendSoap.
//
// Several of the library's response types tag their fields `xml:"onvif:..."`, which
// encoding/xml writes but never matches on read (PTZ positions, imaging settings, endpoint
// addresses); those answers are read with the small structs below instead.
package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/beevik/etree"
	"github.com/use-go/onvif"
	imaging "github.com/use-go/onvif/Imaging"
	"github.com/use-go/onvif/device"
	"github.com/use-go/onvif/event"
	"github.com/use-go/onvif/gosoap"
	"github.com/use-go/onvif/networking"
	"github.com/use-go/onvif/ptz"
	"github.com/use-go/onvif/xsd"
	xsdonvif "github.com/use-go/onvif/xsd/onvif"
)

type subcode struct {
	Value   string
	Subcode *subcode
}

type faultBody struct {
	Body struct {
		Fault *struct {
			Code struct {
				Value   string
				Subcode *subcode
			}
		}
	}
}

// faultText is a fault's code and every subcode, e.g. env:Sender/ter:InvalidArgVal/ter:NoToken.
func faultText(body []byte) string {
	var f faultBody
	if xml.Unmarshal(body, &f) != nil || f.Body.Fault == nil {
		return ""
	}
	out := f.Body.Fault.Code.Value
	for s := f.Body.Fault.Code.Subcode; s != nil; s = s.Subcode {
		out += "/" + s.Value
	}
	return out
}

// result reads a response: its HTTP status, its fault if any, and otherwise decodes into out.
func result(rp reply, out interface{}) map[string]interface{} {
	resp, err := rp.resp, rp.err
	r := map[string]interface{}{}
	if err != nil {
		r["error"] = err.Error()
		return r
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	r["status"] = resp.StatusCode
	if err != nil {
		r["error"] = err.Error()
		return r
	}
	if f := faultText(body); f != "" {
		r["fault"] = f
		return r
	}
	if out != nil {
		if err := xml.Unmarshal(body, out); err != nil {
			r["error"] = err.Error()
		}
	}
	return r
}

// reply is one request's outcome, so it can be handed to result as one argument.
type reply struct {
	resp *http.Response
	err  error
}

func cm(dev *onvif.Device, method interface{}) reply {
	resp, err := dev.CallMethod(method)
	return reply{resp, err}
}

func sa(endpoint, user, password string, method interface{}) reply {
	resp, err := sendAt(endpoint, user, password, method)
	return reply{resp, err}
}

// sendAt posts a library request type to an address CallMethod cannot reach, built exactly as
// CallMethod builds it.
func sendAt(endpoint, user, password string, method interface{}) (*http.Response, error) {
	output, err := xml.MarshalIndent(method, "  ", "    ")
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(string(output)); err != nil {
		return nil, err
	}
	soap := gosoap.NewEmptySOAP()
	soap.AddBodyContent(doc.Root())
	soap.AddRootNamespaces(onvif.Xlmns)
	soap.AddAction()
	soap.AddWSSecurity(user, password)
	return networking.SendSoap(new(http.Client), endpoint, soap.String())
}

type vector struct {
	PanTilt struct {
		X float64 `xml:"x,attr"`
		Y float64 `xml:"y,attr"`
	}
	Zoom struct {
		X float64 `xml:"x,attr"`
	}
}

func (v vector) json() map[string]float64 {
	return map[string]float64{"pan": v.PanTilt.X, "tilt": v.PanTilt.Y, "zoom": v.Zoom.X}
}

type statusEnv struct {
	Body struct {
		GetStatusResponse struct {
			PTZStatus struct {
				Position   vector
				MoveStatus struct {
					PanTilt string
					Zoom    string
				}
				UtcTime string
			}
		}
	}
}

type presetsEnv struct {
	Body struct {
		GetPresetsResponse struct {
			Preset []struct {
				Token       string `xml:"token,attr"`
				Name        string
				PTZPosition vector
			}
		}
	}
}

type subscriptionEnv struct {
	Body struct {
		CreatePullPointSubscriptionResponse struct {
			SubscriptionReference struct {
				Address string
			}
			CurrentTime     string
			TerminationTime string
		}
	}
}

type item struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:"Value,attr"`
}

type pullEnv struct {
	Body struct {
		PullMessagesResponse struct {
			CurrentTime         string
			TerminationTime     string
			NotificationMessage []struct {
				Topic   event.Topic
				Message struct {
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

func notifications(e pullEnv) []map[string]interface{} {
	out := []map[string]interface{}{}
	items := func(list []item) map[string]string {
		m := map[string]string{}
		for _, i := range list {
			m[i.Name] = i.Value
		}
		return m
	}
	for _, n := range e.Body.PullMessagesResponse.NotificationMessage {
		m := n.Message.Message
		out = append(out, map[string]interface{}{
			"topic": string(n.Topic.TopicKinds), "dialect": string(n.Topic.Dialect),
			"utc_time": m.UtcTime, "property_operation": m.PropertyOperation,
			"source": items(m.Source.SimpleItem), "data": items(m.Data.SimpleItem),
		})
	}
	return out
}

type imagingEnv struct {
	Body struct {
		GetImagingSettingsResponse struct {
			ImagingSettings struct {
				Brightness  float64
				Contrast    float64
				IrCutFilter string
			}
		}
	}
}

type focusEnv struct {
	Body struct {
		GetStatusResponse struct {
			Status struct {
				FocusStatus20 struct {
					Position   float64
					MoveStatus string
				}
			}
		}
	}
}

type dateEnv struct {
	Body struct {
		GetSystemDateAndTimeResponse struct {
			SystemDateAndTime struct {
				DateTimeType string
				TimeZone     struct{ TZ string }
				UTCDateTime  struct {
					Time struct{ Hour, Minute, Second int }
					Date struct{ Year, Month, Day int }
				}
			}
		}
	}
}

type scopesEnv struct {
	Body struct {
		GetScopesResponse struct {
			Scopes []xsdonvif.Scope
		}
	}
}

func runServices(dev *onvif.Device, user, password string) {
	out := map[string]interface{}{"endpoints": dev.GetServices()}
	emit := func(v interface{}) {
		b, _ := json.Marshal(v)
		fmt.Println(string(b))
	}
	main := xsdonvif.ReferenceToken("main")
	status := func(key string) {
		var s statusEnv
		r := result(cm(dev, ptz.GetStatus{ProfileToken: main}), &s)
		st := s.Body.GetStatusResponse.PTZStatus
		r["position"] = st.Position.json()
		r["pan_tilt"] = st.MoveStatus.PanTilt
		out[key] = r
	}

	// ---- PTZ ----
	var nodes struct {
		Body struct{ GetNodesResponse ptz.GetNodesResponse }
	}
	r := result(cm(dev, ptz.GetNodes{}), &nodes)
	r["token"] = string(nodes.Body.GetNodesResponse.PTZNode.Token)
	r["max_presets"] = nodes.Body.GetNodesResponse.PTZNode.MaximumNumberOfPresets
	out["nodes"] = r
	out["node"] = result(cm(dev, ptz.GetNode{NodeToken: "ptz_node"}), nil)
	var configs struct {
		Body struct{ GetConfigurationsResponse ptz.GetConfigurationsResponse }
	}
	r = result(cm(dev, ptz.GetConfigurations{}), &configs)
	r["node_token"] = string(configs.Body.GetConfigurationsResponse.PTZConfiguration.NodeToken)
	out["configurations"] = r
	out["configuration"] = result(cm(dev, ptz.GetConfiguration{ProfileToken: "ptz_config"}), nil)
	out["absolute"] = result(cm(dev, ptz.AbsoluteMove{ProfileToken: main, Position: xsdonvif.PTZVector{
		PanTilt: xsdonvif.Vector2D{X: -0.4, Y: 0.3}, Zoom: xsdonvif.Vector1D{X: 0.6}}}), nil)
	status("status_absolute")
	var preset struct {
		Body struct{ SetPresetResponse ptz.SetPresetResponse }
	}
	r = result(cm(dev, ptz.SetPreset{ProfileToken: main, PresetName: "Gate"}), &preset)
	token := preset.Body.SetPresetResponse.PresetToken
	r["token"] = string(token)
	out["set_preset"] = r
	var presets presetsEnv
	r = result(cm(dev, ptz.GetPresets{ProfileToken: main}), &presets)
	list := []map[string]interface{}{}
	for _, p := range presets.Body.GetPresetsResponse.Preset {
		list = append(list, map[string]interface{}{"token": p.Token, "name": p.Name, "position": p.PTZPosition.json()})
	}
	r["presets"] = list
	out["presets"] = r
	out["relative"] = result(cm(dev, ptz.RelativeMove{ProfileToken: main, Translation: xsdonvif.PTZVector{
		PanTilt: xsdonvif.Vector2D{X: 0.2, Y: 0.1}}}), nil)
	status("status_relative")
	out["goto_preset"] = result(cm(dev, ptz.GotoPreset{ProfileToken: main, PresetToken: token}), nil)
	status("status_preset")
	out["continuous"] = result(cm(dev, ptz.ContinuousMove{ProfileToken: main, Velocity: xsdonvif.PTZSpeed{
		PanTilt: xsdonvif.Vector2D{X: 0.3, Y: 0}}, Timeout: "PT20S"}), nil)
	status("status_moving")
	out["stop"] = result(cm(dev, ptz.Stop{ProfileToken: main, PanTilt: true, Zoom: true}), nil)
	status("status_stopped")
	out["refused"] = result(cm(dev, ptz.AbsoluteMove{ProfileToken: main, Position: xsdonvif.PTZVector{
		PanTilt: xsdonvif.Vector2D{X: 0.95, Y: 0}}}), nil)
	status("status_refused")
	out["remove_preset"] = result(cm(dev, ptz.RemovePreset{ProfileToken: main, PresetToken: token}), nil)
	out["home"] = result(cm(dev, ptz.GotoHomePosition{ProfileToken: main}), nil)
	status("status_home")

	// ---- Events ----
	out["event_properties"] = result(cm(dev, event.GetEventProperties{}), nil)
	var sub subscriptionEnv
	r = result(cm(dev, event.CreatePullPointSubscription{
		InitialTerminationTime: event.AbsoluteOrRelativeTimeType{Duration: "PT120S"}}), &sub)
	address := sub.Body.CreatePullPointSubscriptionResponse.SubscriptionReference.Address
	r["address"] = address
	r["termination_time"] = sub.Body.CreatePullPointSubscriptionResponse.TerminationTime
	out["create_pull_point"] = r
	pull := func(key string, timeout string) {
		var p pullEnv
		started := time.Now()
		r := result(sa(address, user, password, event.PullMessages{Timeout: xsd.Duration(timeout), MessageLimit: 10}), &p)
		r["notifications"] = notifications(p)
		r["secs"] = time.Since(started).Seconds()
		out[key] = r
	}
	pull("pull_on_subscribe", "PT5S")
	emit(map[string]string{"step": "subscribed"})
	pull("pull_raised", "PT30S")
	out["sync"] = result(sa(address, user, password, event.SetSynchronizationPoint{}), nil)
	pull("pull_after_sync", "PT5S")
	out["renew"] = result(sa(address, user, password, event.Renew{
		TerminationTime: event.AbsoluteOrRelativeTimeType{Duration: "PT300S"}}), nil)
	out["unsubscribe"] = result(sa(address, user, password, event.Unsubscribe{}), nil)
	pull("pull_after_unsubscribe", "PT1S")

	// ---- Imaging ----
	cam := xsdonvif.ReferenceToken("lobby_cam")
	settings := func(key string) {
		var s imagingEnv
		r := result(cm(dev, imaging.GetImagingSettings{VideoSourceToken: cam}), &s)
		r["brightness"] = s.Body.GetImagingSettingsResponse.ImagingSettings.Brightness
		r["ir_cut_filter"] = s.Body.GetImagingSettingsResponse.ImagingSettings.IrCutFilter
		out[key] = r
	}
	settings("imaging_settings")
	out["imaging_options"] = result(cm(dev, imaging.GetOptions{VideoSourceToken: cam}), nil)
	out["imaging_move_options"] = result(cm(dev, imaging.GetMoveOptions{VideoSourceToken: cam}), nil)
	// The library writes every ImagingSettings20 element, the ones this device does not have
	// (exposure, white balance, wide dynamic range, backlight) included.
	out["imaging_set"] = result(cm(dev, imaging.SetImagingSettings{VideoSourceToken: cam, ImagingSettings: xsdonvif.ImagingSettings20{
		Brightness: 65, ColorSaturation: 50, Contrast: 50, Sharpness: 50, IrCutFilter: "AUTO",
		Focus: xsdonvif.FocusConfiguration20{AutoFocusMode: "AUTO"}}}), nil)
	settings("imaging_settings_after")
	out["imaging_move"] = result(cm(dev, imaging.Move{VideoSourceToken: cam, Focus: xsdonvif.FocusMove{
		Absolute: xsdonvif.AbsoluteFocus{Position: 0.7, Speed: 0.5}}}), nil)
	var focus focusEnv
	r = result(cm(dev, imaging.GetStatus{VideoSourceToken: cam}), &focus)
	r["position"] = focus.Body.GetStatusResponse.Status.FocusStatus20.Position
	out["imaging_status"] = r
	out["imaging_stop"] = result(cm(dev, imaging.Stop{VideoSourceToken: cam}), nil)

	// ---- Device Set* ----
	hostname := func(key string) {
		var h struct {
			Body struct{ GetHostnameResponse device.GetHostnameResponse }
		}
		r := result(cm(dev, device.GetHostname{}), &h)
		r["name"] = string(h.Body.GetHostnameResponse.HostnameInformation.Name)
		out[key] = r
	}
	hostname("hostname_initial")
	out["set_hostname"] = result(cm(dev, device.SetHostname{Name: "gate-cam"}), nil)
	hostname("hostname_after")
	out["set_scopes"] = result(cm(dev, device.SetScopes{Scopes: "onvif://www.onvif.org/location/gate"}), nil)
	out["add_scopes"] = result(cm(dev, device.AddScopes{ScopeItem: "onvif://www.onvif.org/name/Gate"}), nil)
	out["remove_scopes"] = result(cm(dev, device.RemoveScopes{ScopeItem: "onvif://www.onvif.org/location/gate"}), nil)
	var scopes scopesEnv
	r = result(cm(dev, device.GetScopes{}), &scopes)
	configurable := []string{}
	for _, s := range scopes.Body.GetScopesResponse.Scopes {
		if s.ScopeDef == "Configurable" {
			configurable = append(configurable, string(s.ScopeItem))
		}
	}
	r["configurable"] = configurable
	out["scopes"] = r
	var reboot struct {
		Body struct{ SystemRebootResponse device.SystemRebootResponse }
	}
	r = result(cm(dev, device.SystemReboot{}), &reboot)
	r["message"] = reboot.Body.SystemRebootResponse.Message
	out["reboot"] = r
	when := time.Now().UTC().Add(90 * time.Second)
	out["date_time_asked"] = when.Format(time.RFC3339)
	out["set_date_time"] = result(cm(dev, device.SetSystemDateAndTime{
		DateTimeType: "Manual", TimeZone: xsdonvif.TimeZone{TZ: "UTC0"},
		UTCDateTime: xsdonvif.DateTime{
			Time: xsdonvif.Time{Hour: xsd.Int(when.Hour()), Minute: xsd.Int(when.Minute()), Second: xsd.Int(when.Second())},
			Date: xsdonvif.Date{Year: xsd.Int(when.Year()), Month: xsd.Int(when.Month()), Day: xsd.Int(when.Day())}}}), nil)
	var date dateEnv
	r = result(cm(dev, device.GetSystemDateAndTime{}), &date)
	d := date.Body.GetSystemDateAndTimeResponse.SystemDateAndTime
	r["type"] = d.DateTimeType
	r["utc"] = time.Date(d.UTCDateTime.Date.Year, time.Month(d.UTCDateTime.Date.Month), d.UTCDateTime.Date.Day,
		d.UTCDateTime.Time.Hour, d.UTCDateTime.Time.Minute, d.UTCDateTime.Time.Second, 0, time.UTC).Format(time.RFC3339)
	out["date_time_after"] = r
	emit(out)
	os.Exit(0)
}
