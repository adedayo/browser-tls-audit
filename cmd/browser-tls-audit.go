package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"sync"

	homedir "github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/acme/autocert"
)

var (
	messageBus = make(chan interface{})
	helloInfos = make(map[string]*tls.ClientHelloInfo) // remote address by hello info
	helloMutex = sync.RWMutex{}
	infoWriter = make(chan tlsInfoAndAgent)
	cachePath  = func() (certHome string) {
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
	domain, rawtlsPort = getFlags()
	certManager        = autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      autocert.DirCache(cachePath),
	}
)

type remoteAddressAndAgent struct {
	remote string
	agent  string
}

type tlsInfoAndAgent struct {
	Agent     string
	HelloInfo *tls.ClientHelloInfo
}

func main() {

	println(domain, rawtlsPort)
	go rawTLS(rawtlsPort)
	go https(rawtlsPort + 1)
	go readMessages()

	for info := range infoWriter {
		fmt.Printf("Got Info %#v\n", info)
	}
}

func getFlags() (string, int) {

	domain := flag.String("domain", "hostname", "The public domain name of this server")
	port := flag.Int("port", 54320, "The port of the raw TLS server socket, the HTTPS port is +1 that value")
	flag.Parse()
	return *domain, *port
}

func readMessages() {
	for event := range messageBus {
		switch data := event.(type) {
		case remoteAddressAndAgent:
			helloMutex.RLock()
			if hello, present := helloInfos[data.remote]; present {
				infoWriter <- tlsInfoAndAgent{
					Agent:     data.agent,
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
	// certificatePath := "certs/serverRSA.crt"
	// keyPath         := "certs/serverRSA.key"
	// cert, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	conf := getTLSConfig()
	// conf.Certificates = []tls.Certificate{cert}

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
		go handleConnection(c)
	}
}

func https(port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/browserAudit", auditBrowser)
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", port),
		Handler:   mux,
		TLSConfig: getTLSConfig(),
	}
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func getTLSConfig() *tls.Config {
	return &tls.Config{
		GetConfigForClient:       clientConfigGetter,
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		GetCertificate:           certManager.GetCertificate,
	}
}

func auditBrowser(w http.ResponseWriter, req *http.Request) {
	messageBus <- remoteAddressAndAgent{
		remote: req.RemoteAddr,
		agent:  req.UserAgent(),
	}

	address := req.RemoteAddr
	helloMutex.RLock()
	if hello, present := helloInfos[address]; present {
		data := tlsInfoAndAgent{
			Agent:     req.UserAgent(),
			HelloInfo: hello,
		}
		if js, err := json.Marshal(data); err == nil {
			w.Header().Set("Content-Type", "text/json")
			w.Write(js)
			println(string(js))
		}
	}
	helloMutex.RUnlock()
}

func clientConfigGetter(helloInfo *tls.ClientHelloInfo) (conf *tls.Config, err error) {
	messageBus <- helloInfo
	return
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	//do whatever you like with the connection
}