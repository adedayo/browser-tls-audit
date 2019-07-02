package model

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"testing"
)

func TestBrowserfromUserAgent(t *testing.T) {

	in, err := os.OpenFile("../browser-data.json", os.O_RDONLY, 0644)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer in.Close()
	dec := json.NewDecoder(in)
	out := []TLSInfoAndAgent{}
	for {

		if len(out) > 5000 { //return no more than 5000 records
			break
		}
		info := TLSInfoAndAgent{}
		if err := dec.Decode(&info); err == io.EOF {
			break
		} else if err == nil {
			t.Run(info.Agent, func(t *testing.T) {
				if _, err := getBrowserVersionAndOS(info.Agent); err != nil {
					t.Error(err.Error())
				}
			})
		} else {
			t.Error(err.Error())
		}
	}

}
