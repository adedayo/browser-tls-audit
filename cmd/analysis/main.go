package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"time"

	bta "github.com/adedayo/browser-tls-audit/pkg"
)

func main() {
	data := bta.GetEnrichedData(".")
	dataPath := path.Join("data", "enriched-browser-data.json")
	if _, err := os.Stat(dataPath); !os.IsNotExist(err) {
		//there is an existing data, back it up.
		if d, err := ioutil.ReadFile(dataPath); err == nil {
			caps := bta.TLSCapabilities{}
			if err := json.Unmarshal(d, &caps); err == nil {
				if err := os.Rename(dataPath, path.Join("data", fmt.Sprintf("%s-enriched-browser-data.json", caps.Timestamp.Format("20060102")))); err != nil {
					log.Fatal(err)
					return
				}
			} else {
				log.Fatal(err)
				return
			}
		}
	}

	out, err := os.OpenFile(dataPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer out.Close()

	caps := bta.TLSCapabilities{
		Timestamp:    time.Now(),
		Capabilities: data,
	}
	if js, err := json.MarshalIndent(caps, "", " "); err == nil {
		out.Write(js)
		out.Sync()
	} else {
		log.Fatal(err)
	}
}
