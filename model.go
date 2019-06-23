package model

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strconv"
)

type RemoteAddressAndAgent struct {
	Remote string
	Agent  string
}

type TLSInfoAndAgent struct {
	Agent     string
	HelloInfo *tls.ClientHelloInfo
}

func (t TLSInfoAndAgent) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"Agent": t.Agent,
		"HelloInfo": map[string]interface{}{
			"ServerName":        t.HelloInfo.ServerName,
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
			} else {
				return fmt.Errorf("Expects a string %s, but got %#v", k, v)
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
					} else {
						return fmt.Errorf("Expects a string %s, but got %#v", k2, v2)
					}
				case "SupportedProtos":
					if sp, ok := v2.([]interface{}); ok {
						for _, p := range sp {
							if proto, ok := p.(string); ok {
								hi.SupportedProtos = append(hi.SupportedProtos, proto)
							} else {
								return fmt.Errorf("Expects a string, but got %#v", p)
							}
						}
					} else {
						return fmt.Errorf("Expects a string slice %s, but got %#v", k2, v2)
					}
				case "CipherSuites":
					if cs, err := parseUint16Strings(k2, v2); err == nil {
						hi.CipherSuites = cs
					} else {
						return err
					}
				case "SupportedCurves":
					if cs, err := parseCurveStrings(k2, v2); err == nil {
						hi.SupportedCurves = cs
					} else {
						return err
					}
				case "SupportedPoints":
					if cs, err := parsePointsStrings(k2, v2); err == nil {
						hi.SupportedPoints = cs
					} else {
						return err
					}
				case "SupportedSchemes":
					if cs, err := parseSchemesStrings(k2, v2); err == nil {
						hi.SignatureSchemes = cs
					} else {
						return err
					}
				case "SupportedVersions":
					if cs, err := parseUint16Strings(k2, v2); err == nil {
						hi.SupportedVersions = cs
					} else {
						return err
					}
				}
			}
			t.HelloInfo = &hi
		default:
			return fmt.Errorf("Unexpected field %s with value %#v", k, v)
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
