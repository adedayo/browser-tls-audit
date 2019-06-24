package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"

	bta "github.com/adedayo/browser-tls-audit"
	homedir "github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/acme/autocert"
)

var (
	messageBus = make(chan interface{})
	helloInfos = make(map[string]*tls.ClientHelloInfo) // remote address by hello info
	helloMutex = sync.RWMutex{}
	infoWriter = make(chan bta.TLSInfoAndAgent)
	dataDir    = func() (dataHome string) {
		if home, err := homedir.Dir(); err == nil {
			dataHome = path.Join(home, "browserdata")
			//create if it doesn't exist
			if _, err := os.Stat(dataHome); os.IsNotExist(err) {
				if err2 := os.MkdirAll(dataHome, 0755); err2 != nil {
					log.Println("Could not create the path: ", dataHome)
				}
			}
		}
		return
	}()
	certCachePath = func() (certHome string) {
		if home, err := homedir.Dir(); err == nil {
			certHome = path.Join(home, "certs")
			//create certs home if it doesn't exist
			if _, err := os.Stat(certHome); os.IsNotExist(err) {
				if err2 := os.MkdirAll(certHome, 0755); err2 != nil {
					log.Println("Could not create the path: ", certHome)
				}
			}
		}
		return
	}()
	domain, httpsPort, certificatePath, keyPath = getFlags()
	certManager                                 = autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(strings.Split(domain, ",")...),
		Cache:      autocert.DirCache(certCachePath),
	}
)

func main() {
	fmt.Printf("Bound to domain %s using HTTPS port %d\n", domain, httpsPort)
	go rawTLS(httpsPort - 1)
	go https(httpsPort)
	go readMessages()
	writeMessages()
}

func getFlags() (domain string, port int, cert, key string) {
	dd := flag.String("domain", "hostname", "The public domain name of this server")
	pp := flag.Int("port", 443, "The HTTPS port. The the raw TLS server socket is the (HTTPS port) - 1")
	cc := flag.String("cert", "", "The certificate file to use (optional), will attempt to get a cert from Letsencrypt if not specified")
	kk := flag.String("key", "", "The certificate key file to use (optional), will attempt to get a key from Letsencrypt if not specified")
	flag.Parse()
	return *dd, *pp, *cc, *kk
}

func writeMessages() {
	out, err := os.OpenFile(path.Join(dataDir, "browser-data.json"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer out.Close()

	buff := bytes.Buffer{}
	writer := bufio.NewWriter(&buff)
	tee := io.MultiWriter(out, writer)
	je := json.NewEncoder(tee)

	for info := range infoWriter {
		je.Encode(info)
		writer.Flush()
		out.Sync()
		// info := bta.TLSInfoAndAgent{}
		// data := buff.Bytes()
		// err := json.Unmarshal(data, &info)
		// if err != nil {
		// 	fmt.Printf("Got Error %s:\n%s\n", err.Error(), string(data))
		// } else {
		// 	fmt.Printf("Got Info %#v\n, %#v\n %s\n", info, info.HelloInfo, string(data))
		// }
	}
}

func readMessages() {
	for event := range messageBus {
		switch data := event.(type) {
		case bta.RemoteAddressAndAgent:
			helloMutex.RLock()
			if hello, present := helloInfos[data.Remote]; present {
				infoWriter <- bta.TLSInfoAndAgent{
					Agent:     data.Agent,
					HelloInfo: hello,
				}
			} // else ignore agent without pior tls info

			helloMutex.RUnlock()
		case *tls.ClientHelloInfo:
			helloMutex.Lock()
			address := data.Conn.RemoteAddr().String()
			if _, present := helloInfos[address]; !present {
				helloInfos[address] = data
			}
			helloMutex.Unlock()
		default:
			fmt.Printf("Unknown type %#v\n", data)
		}
	}
}

func rawTLS(port int) {
	conf := getTLSConfig()
	conn, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), conf)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	for {
		c, err := conn.Accept()
		if err != nil {
			log.Fatal(err)
		}
		c.Close()
	}
}

func https(port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/browserAudit", auditBrowser)
	mux.HandleFunc("/browserTLSResults", showResults)
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", port),
		Handler:   mux,
		TLSConfig: getTLSConfig(),
	}

	go http.ListenAndServe(":http", certManager.HTTPHandler(nil))

	log.Fatal(server.ListenAndServeTLS("", ""))
}

func getTLSConfig() *tls.Config {
	return &tls.Config{
		GetConfigForClient:       clientConfigGetter,
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		GetCertificate:           getLocalOrAutoCert(),
		Certificates:             getLocalCerts(),
	}
}

func getLocalCerts() (certs []tls.Certificate) {
	if len(certificatePath) > 0 && len(keyPath) > 0 {
		cert, err := tls.LoadX509KeyPair(certificatePath, keyPath)
		if err != nil {
			log.Fatal(err)
			return
		}
		certs = append(certs, cert)
	}
	return
}

func getLocalOrAutoCert() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if len(certificatePath) > 0 && len(keyPath) > 0 {
		return nil
	}
	return certManager.GetCertificate
}

func showResults(w http.ResponseWriter, req *http.Request) {
	in, err := os.OpenFile(path.Join(dataDir, "browser-data.json"), os.O_RDONLY, 0644)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer in.Close()
	dec := json.NewDecoder(in)
	out := []bta.TLSInfoAndAgent{}
	for {
		if len(out) > 5000 { //return no more than 5000 records
			break
		}
		info := bta.TLSInfoAndAgent{}
		if err := dec.Decode(&info); err == io.EOF {
			break
		} else if err == nil {
			out = append(out, info)
		} else {
			println(err.Error())
		}
	}
	w.Header().Set("Content-Type", "text/html")
	json.NewEncoder(w).Encode(out)
}

func auditBrowser(w http.ResponseWriter, req *http.Request) {
	messageBus <- bta.RemoteAddressAndAgent{
		Remote: req.RemoteAddr,
		Agent:  req.UserAgent(),
	}

	address := req.RemoteAddr
	helloMutex.RLock()
	if hello, present := helloInfos[address]; present {
		data := bta.TLSInfoAndAgent{
			Agent:     req.UserAgent(),
			HelloInfo: hello,
		}
		if js, err := json.Marshal(data); err == nil {
			w.Header().Set("Content-Type", "text/html")
			w.Write(js)
		}
	}
	helloMutex.RUnlock()
}

func clientConfigGetter(helloInfo *tls.ClientHelloInfo) (*tls.Config, error) {
	messageBus <- helloInfo
	return nil, nil
}
