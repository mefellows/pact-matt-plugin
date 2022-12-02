//go:build provider
// +build provider

package plugin

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	// "github.com/pact-foundation/pact-go/v2/log"
	"log"

	"github.com/pact-foundation/pact-go/v2/provider"
	"github.com/stretchr/testify/assert"
)

var dir, _ = os.Getwd()
var pactDir = fmt.Sprintf("%s/pacts", dir)

func TestPluginProvider(t *testing.T) {
	// Start provider API in the background
	go startHTTPProvider()
	go startTCPServer(8444)

	verifier := provider.NewVerifier()

	// Verify the Provider with local Pact Files
	err := verifier.VerifyProvider(t, provider.VerifyRequest{
		ProviderBaseURL: "http://localhost:8333",
		Provider:        "provider",
		PactFiles: []string{
			filepath.ToSlash(fmt.Sprintf("%s/MattConsumer-MattProvider.json", pactDir)),
			filepath.ToSlash(fmt.Sprintf("%s/matttcpconsumer-matttcpprovider.json", pactDir)),
		},
		Transports: []provider.Transport{
			provider.Transport{
				Protocol: "matt",
				Port:     8444,
				Scheme:   "tcp",
			},
		},
	})

	assert.NoError(t, err)
}

func startHTTPProvider() {
	mux := http.NewServeMux()

	mux.HandleFunc("/matt", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Content-Type", "application/matt")
		fmt.Fprintf(w, `MATTworldMATT`)
		w.WriteHeader(200)
	})

	log.Fatal(http.ListenAndServe("localhost:8333", mux))
}

func startTCPServer(port int) {
	log.Println("[INFO] TCP server on port", port)
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Println("[INFO] :", err)
	}

	log.Println("[INFO] server started on port", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("[INFO] connection error:", err)
			continue
		}

		log.Println("[INFO] connection established with:", conn.RemoteAddr())

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	log.Println("[INFO] TCP connection")
	defer conn.Close()

	s := bufio.NewScanner(conn)

	for s.Scan() {

		data := s.Text()
		log.Println("[INFO] received from connection", data)

		if data == "" {
			continue
		}

		handleRequest(data, conn)
	}
}

func handleRequest(req string, conn net.Conn) {
	log.Println("[INFO] Server received request", req, "on connection", conn)

	if !isValidMessage(req) {
		log.Println("[INFO] Server received invalid request, erroring")
		conn.Write([]byte("ERROR\n"))
	}
	log.Println("[INFO] Server received valid request, responding")

	// var expectedResponse = "badworld"
	var expectedResponse = "tcpworld"
	conn.Write([]byte(generateMattMessage(expectedResponse)))
	conn.Write([]byte("\n"))
}

func generateMattMessage(message string) string {
	return fmt.Sprintf("MATT%sMATT", message)
}

func parseMattMessage(message string) string {
	return strings.ReplaceAll(message, "MATT", "")
}

func isValidMessage(str string) bool {
	matched, err := regexp.MatchString(`^MATT.*MATT$`, str)
	if err != nil {
		return false
	}

	return matched
}
