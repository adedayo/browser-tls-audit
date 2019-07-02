package model

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"os"
	"path"

	tlsdefs "github.com/adedayo/tls-definitions"
)

//GetEnrichedData retrieves browser TLS audit data with further enrichment and annotations
func GetEnrichedData(dataDir string) (out []TLSClientCapability) {
	data := GetRawData(dataDir)
	for _, d := range data {
		out = append(out, TLSClientCapability{
			ClientDescription: getClientDescription(d.Agent),
			Agent:             d.Agent,
			Capability:        getTLSCapability(d.HelloInfo),
		})
	}
	return
}

//GetRawData retrieves browser TLS audit data
func GetRawData(dataDir string) (out []TLSInfoAndAgent) {
	in, err := os.OpenFile(path.Join(dataDir, "browser-data.json"), os.O_RDONLY, 0644)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer in.Close()
	dec := json.NewDecoder(in)
	for {
		if len(out) > 5000 { //return no more than 5000 records
			break
		}
		info := TLSInfoAndAgent{}
		if err := dec.Decode(&info); err == io.EOF {
			break
		} else if err == nil {
			out = append(out, info)
		} else {
			println(err.Error())
		}
	}

	return
}

func getClientDescription(ua string) (desc ClientDescription) {
	if br, err := getBrowserVersionAndOS(ua); err == nil {
		desc.Browser = br.name
		desc.BrowserVersion = br.version
		desc.OS = br.os
	}
	return
}

func getTLSCapability(h *tls.ClientHelloInfo) TLSCapability {
	cap := TLSCapability{
		ClientHelloInfo: *h,
	}
	// cap.CipherSuites = h.CipherSuites
	for _, c := range h.CipherSuites {
		if cipher, ok := tlsdefs.CipherSuiteMap[c]; ok {
			cap.CipherSuiteNames = append(cap.CipherSuiteNames, cipher)
		} else {
			cap.CipherSuiteNames = append(cap.CipherSuiteNames, hex([]uint16{c})[0])
		}
	}
	for _, c := range h.SupportedCurves {
		if sc, ok := tlsdefs.SupportedGroups[uint16(c)]; ok {
			cap.SupportedCurveNames = append(cap.SupportedCurveNames, sc)
		} else {
			cap.SupportedCurveNames = append(cap.SupportedCurveNames, hex([]uint16{uint16(c)})[0])
		}
	}

	for _, c := range h.SignatureSchemes {
		if ss, ok := tlsdefs.SignatureSchemes[uint16(c)]; ok {
			cap.SignatureSchemeNames = append(cap.SignatureSchemeNames, ss)
		} else {
			cap.SignatureSchemeNames = append(cap.SignatureSchemeNames, hex([]uint16{uint16(c)})[0])
		}
	}

	for _, c := range h.SupportedVersions {
		if p, ok := tlsdefs.TLSVersionMap[c]; ok {
			cap.SupportedVersionNames = append(cap.SupportedVersionNames, p)
		} else {
			cap.SupportedVersionNames = append(cap.SupportedVersionNames, hex([]uint16{c})[0])
		}
	}

	return cap
}
