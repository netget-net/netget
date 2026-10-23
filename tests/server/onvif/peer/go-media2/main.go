// Media2 through github.com/IOTechSystems/onvif (the ONVIF library EdgeX's device-onvif-camera
// uses): NewDevice (GetCapabilities with a WS-Security digest), then the library's media2
// request and response types — GetProfiles and GetVideoEncoderConfigurations, the Media2
// operations it implements. The library sends Media2 to the Media service's XAddr ("Media2 uses
// the same endpoint but different XML name space"). Prints one JSON object.
// Usage: onvif-go-media2 host:port username password
package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"

	"github.com/IOTechSystems/onvif"
	"github.com/IOTechSystems/onvif/media2"
)

type subcode struct {
	Value   string
	Subcode *subcode
}

func call(dev *onvif.Device, request interface{}, out interface{}) map[string]interface{} {
	r := map[string]interface{}{}
	resp, err := dev.CallMethod(request)
	if err != nil {
		r["error"] = err.Error()
		return r
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	r["status"] = resp.StatusCode
	var f struct {
		Body struct {
			Fault *struct {
				Code struct {
					Value   string
					Subcode *subcode
				}
			}
		}
	}
	if xml.Unmarshal(body, &f) == nil && f.Body.Fault != nil {
		text := f.Body.Fault.Code.Value
		for s := f.Body.Fault.Code.Subcode; s != nil; s = s.Subcode {
			text += "/" + s.Value
		}
		r["fault"] = text
		return r
	}
	if err := xml.Unmarshal(body, out); err != nil {
		r["error"] = err.Error()
	}
	return r
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: onvif-go-media2 host:port username password")
		os.Exit(2)
	}
	out := map[string]interface{}{}
	dev, err := onvif.NewDevice(onvif.DeviceParams{Xaddr: os.Args[1], Username: os.Args[2], Password: os.Args[3], AuthMode: onvif.UsernameTokenAuth})
	if err != nil {
		out["connect_error"] = err.Error()
	} else {
		out["endpoints"] = dev.GetServices()
		var profiles struct {
			Body struct{ GetProfilesResponse media2.GetProfilesResponse }
		}
		r := call(dev, media2.GetProfiles{}, &profiles)
		list := []map[string]interface{}{}
		for _, p := range profiles.Body.GetProfilesResponse.Profiles {
			list = append(list, map[string]interface{}{"token": p.Token, "name": p.Name, "fixed": p.Fixed})
		}
		r["profiles"] = list
		out["profiles"] = r
		var encoders struct {
			Body struct {
				GetVideoEncoderConfigurationsResponse media2.GetVideoEncoderConfigurationsResponse
			}
		}
		r = call(dev, media2.GetVideoEncoderConfigurations{ProfileToken: "main"}, &encoders)
		configs := []map[string]interface{}{}
		for _, c := range encoders.Body.GetVideoEncoderConfigurationsResponse.Configurations {
			e := map[string]interface{}{"token": string(c.Token), "name": string(c.Name)}
			if c.Encoding != nil {
				e["encoding"] = string(*c.Encoding)
			}
			if c.Resolution != nil && c.Resolution.Width != nil && c.Resolution.Height != nil {
				e["width"], e["height"] = int(*c.Resolution.Width), int(*c.Resolution.Height)
			}
			if c.RateControl != nil {
				e["rate_control"] = c.RateControl
			}
			configs = append(configs, e)
		}
		r["configurations"] = configs
		out["encoders"] = r
		var all struct {
			Body struct {
				GetVideoEncoderConfigurationsResponse media2.GetVideoEncoderConfigurationsResponse
			}
		}
		out["all_encoders"] = call(dev, media2.GetVideoEncoderConfigurations{}, &all)
		out["all_encoder_count"] = len(all.Body.GetVideoEncoderConfigurationsResponse.Configurations)
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}
