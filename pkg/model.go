package model

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

//TLSCapabilities is the collection of all recorded capabilities
type TLSCapabilities struct {
	Timestamp    time.Time
	Capabilities []TLSClientCapability
}

//TLSClientCapability represents a the capabilities and other properties of a TLS client
type TLSClientCapability struct {
	ClientDescription ClientDescription
	Agent             string
	Capability        TLSCapability
}

//MarshalJSON serialises TLSCapability to JSON
func (t TLSCapability) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"SupportedProtos":       t.SupportedProtos,
		"CipherSuites":          hex(t.CipherSuites),
		"CipherSuiteNames":      t.CipherSuiteNames,
		"SupportedCurves":       hexCurve(t.SupportedCurves),
		"SupportedCurveNames":   t.SupportedCurveNames,
		"SupportedPoints":       hex8(t.SupportedPoints),
		"SupportedSchemes":      hexSignature(t.SignatureSchemes),
		"SupportedSchemeNames":  t.SupportedCurveNames,
		"SupportedVersions":     hex(t.SupportedVersions),
		"SupportedVersionNames": t.SupportedVersionNames,
	}
	return json.Marshal(m)
}

//UnmarshalJSON deserialises TLSCapability from JSON
func (t *TLSCapability) UnmarshalJSON(data []byte) error {
	m := map[string]interface{}{}
	err := json.Unmarshal(data, &m)
	if err != nil {
		return err
	}

	for k2, v2 := range m {
		switch k2 {
		case "SupportedProtos":
			if sp, ok := v2.([]interface{}); ok {
				for _, p := range sp {
					if proto, ok := p.(string); ok {
						t.SupportedProtos = append(t.SupportedProtos, proto)
					}
				}
			}
		case "CipherSuites":
			if cs, err := parseUint16Strings(k2, v2); err == nil {
				t.CipherSuites = cs
			}
		case "CiperSuiteNames":
			if names, ok := v2.([]interface{}); ok {
				for _, n := range names {
					if name, ok := n.(string); ok {
						t.CipherSuiteNames = append(t.CipherSuiteNames, name)
					}
				}
			}
		case "SupportedCurves":
			if cs, err := parseCurveStrings(k2, v2); err == nil {
				t.SupportedCurves = cs
			}
		case "SupportedCurveNames":
			if names, ok := v2.([]interface{}); ok {
				for _, n := range names {
					if name, ok := n.(string); ok {
						t.SupportedCurveNames = append(t.SupportedCurveNames, name)
					}
				}
			}
		case "SupportedPoints":
			if cs, err := parsePointsStrings(k2, v2); err == nil {
				t.SupportedPoints = cs
			}
		case "SupportedSchemes":
			if cs, err := parseSchemesStrings(k2, v2); err == nil {
				t.SignatureSchemes = cs
			}
		case "SignatureSchemeNames":
			if names, ok := v2.([]interface{}); ok {
				for _, n := range names {
					if name, ok := n.(string); ok {
						t.SignatureSchemeNames = append(t.SignatureSchemeNames, name)
					}
				}
			}
		case "SupportedVersions":
			if cs, err := parseUint16Strings(k2, v2); err == nil {
				t.SupportedVersions = cs
			}
		case "SupportedVersionNames":
			if names, ok := v2.([]interface{}); ok {
				for _, n := range names {
					if name, ok := n.(string); ok {
						t.SupportedVersionNames = append(t.SupportedVersionNames, name)
					}
				}
			}
		}
	}
	return nil
}

//RemoteAddressAndAgent is the remote browser's address and user agent information
type RemoteAddressAndAgent struct {
	Remote string
	Agent  string
}

//TLSInfoAndAgent contains the browser's user agent and ClientHelloInfo (TLS capability fingerprint)
type TLSInfoAndAgent struct {
	Agent     string
	HelloInfo *tls.ClientHelloInfo
}

//TLSCapability essentially mirrors HelloInfo
type TLSCapability struct {
	tls.ClientHelloInfo
	// CipherSuites          []uint16
	CipherSuiteNames []string
	// SupportedCurves       []uint16
	SupportedCurveNames []string
	// SupportedPoints       []uint8
	SignatureSchemeNames []string
	// SupportedProtos       []string
	// SupportedVersions     []uint16
	SupportedVersionNames []string
}

//ClientDescription represents a TLS client browser, its version and operating system
type ClientDescription struct {
	Browser        string
	BrowserVersion string
	OS             string
}

//MarshalJSON serialises TLSInfoAndAgent to JSON
func (t TLSInfoAndAgent) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"Agent": t.Agent,
		"HelloInfo": map[string]interface{}{
			// "ServerName":        t.HelloInfo.ServerName, //not useful
			"SupportedProtos":   t.HelloInfo.SupportedProtos,
			"CipherSuites":      hex(t.HelloInfo.CipherSuites),
			"SupportedCurves":   hexCurve(t.HelloInfo.SupportedCurves),
			"SupportedPoints":   hex8(t.HelloInfo.SupportedPoints),
			"SupportedSchemes":  hexSignature(t.HelloInfo.SignatureSchemes),
			"SupportedVersions": hex(t.HelloInfo.SupportedVersions),
		},
	}
	return json.Marshal(m)
}

//UnmarshalJSON deserialises TLSInfoAndAgent from JSON
func (t *TLSInfoAndAgent) UnmarshalJSON(data []byte) error {
	m := map[string]interface{}{}
	err := json.Unmarshal(data, &m)
	if err != nil {
		return err
	}
	for k, v := range m {
		switch k {
		case "Agent":
			if agent, ok := v.(string); ok {
				t.Agent = agent
			}
		case "HelloInfo":
			hi := tls.ClientHelloInfo{}
			m2, ok := v.(map[string]interface{})
			if !ok {
				return fmt.Errorf("Expects a map but got %#v", v)
			}

			for k2, v2 := range m2 {
				switch k2 {
				case "ServerName":
					if sn, ok := v2.(string); ok {
						hi.ServerName = sn
					}
				case "SupportedProtos":
					if sp, ok := v2.([]interface{}); ok {
						for _, p := range sp {
							if proto, ok := p.(string); ok {
								hi.SupportedProtos = append(hi.SupportedProtos, proto)
							}
						}
					}
				case "CipherSuites":
					if cs, err := parseUint16Strings(k2, v2); err == nil {
						hi.CipherSuites = cs
					}
				case "SupportedCurves":
					if cs, err := parseCurveStrings(k2, v2); err == nil {
						hi.SupportedCurves = cs
					}
				case "SupportedPoints":
					if cs, err := parsePointsStrings(k2, v2); err == nil {
						hi.SupportedPoints = cs
					}
				case "SupportedSchemes":
					if cs, err := parseSchemesStrings(k2, v2); err == nil {
						hi.SignatureSchemes = cs
					}
				case "SupportedVersions":
					if cs, err := parseUint16Strings(k2, v2); err == nil {
						hi.SupportedVersions = cs
					}
				}
			}
			t.HelloInfo = &hi
		default:
			// return fmt.Errorf("Unexpected field %s with value %#v", k, v)
		}
	}
	return nil
}

func parseSchemesStrings(k string, v interface{}) ([]tls.SignatureScheme, error) {
	cs := []tls.SignatureScheme{}
	if ccc, ok := v.([]interface{}); ok {
		for _, c := range ccc {
			if cc, ok := c.(string); ok {
				if x, err := strconv.ParseUint(cc, 0, 0); err == nil {
					cs = append(cs, tls.SignatureScheme(x))
				} else {
					return cs, err
				}
			} else {
				return cs, fmt.Errorf("Expects a string, but got %#v", c)
			}
		}
		return cs, nil
	}
	return cs, fmt.Errorf("Expects a string slice %s, but got %#v", k, v)
}

func parsePointsStrings(k string, v interface{}) ([]uint8, error) {
	cs := []uint8{}
	if ccc, ok := v.([]interface{}); ok {
		for _, c := range ccc {
			if cc, ok := c.(string); ok {
				if x, err := strconv.ParseUint(cc, 0, 0); err == nil {
					cs = append(cs, uint8(x))
				} else {
					return cs, err
				}
			} else {
				return cs, fmt.Errorf("Expects a string, but got %#v", c)
			}

		}
		return cs, nil
	}
	return cs, fmt.Errorf("Expects a string slice %s, but got %#v", k, v)
}

func parseCurveStrings(k string, v interface{}) ([]tls.CurveID, error) {
	cs := []tls.CurveID{}
	if ccc, ok := v.([]interface{}); ok {
		for _, c := range ccc {
			if cc, ok := c.(string); ok {
				if x, err := strconv.ParseUint(cc, 0, 0); err == nil {
					cs = append(cs, tls.CurveID(x))
				} else {
					return cs, err
				}
			} else {
				return cs, fmt.Errorf("Expects a string, but got %#v", c)
			}

		}
		return cs, nil
	}
	return cs, fmt.Errorf("Expects a string slice %s, but got %#v", k, v)
}

func parseUint16Strings(k string, v interface{}) ([]uint16, error) {
	cs := []uint16{}
	if ccc, ok := v.([]interface{}); ok {

		for _, c := range ccc {
			if cc, ok := c.(string); ok {
				if x, err := strconv.ParseUint(cc, 0, 0); err == nil {
					cs = append(cs, uint16(x))
				} else {
					return cs, err
				}
			} else {
				return cs, fmt.Errorf("Expects a string but got %#v", c)
			}

		}
		return cs, nil
	}
	return cs, fmt.Errorf("Expects a string slice %s, but got %#v", k, v)
}

func hex(data []uint16) (out []string) {
	for _, x := range data {
		out = append(out, fmt.Sprintf("0x%04x", x))
	}
	return
}

func hex8(data []uint8) (out []string) {
	for _, x := range data {
		out = append(out, fmt.Sprintf("0x%02x", x))
	}
	return
}

func hexCurve(data []tls.CurveID) (out []string) {
	for _, x := range data {
		out = append(out, fmt.Sprintf("0x%04x", x))
	}
	return
}

func hexSignature(data []tls.SignatureScheme) (out []string) {
	for _, x := range data {
		out = append(out, fmt.Sprintf("0x%04x", x))
	}
	return
}
