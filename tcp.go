package main

import (
	"bufio"
	"fmt"
	"log"
	"net"

	plugin "github.com/mefellows/pact-matt-plugin/io_pact_plugin"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var servers = map[string]net.Listener{}

func startTCPServer(id string, port int, expectedMessage string, responseMessage string, mismatches map[string]*plugin.ContentMismatches) {
	log.Println("[INFO] TCP server", id, "on port", port)
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Println("[INFO] :", err)
	}
	servers[id] = listener
	log.Println("[INFO] server started", id, "on port", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("[ERROR] TCP connection error:", err)
			log.Println("[INFO] Shutting down TCP listener")
			break
		}

		log.Println("[INFO] TCP connection established with:", conn.RemoteAddr())

		go handleConnection(conn, expectedMessage, responseMessage, mismatches)
	}
}

func stopTCPServer(id string) error {
	log.Println("[INFO] shutting down TCP Server")

	// TODO: properly handle this, and send a signal to the handler to stop listening
	return servers[id].Close()
}

func handleConnection(conn net.Conn, expectedMessage string, responseMessage string, mismatches map[string]*plugin.ContentMismatches) {
	log.Println("[INFO] handling TCP connection")

	defer conn.Close()

	s := bufio.NewScanner(conn)

	for s.Scan() {

		data := s.Text()
		log.Println("[DEBUG] received from connection", data)

		if data == "" {
			continue
		}

		handleRequest(data, conn, expectedMessage, responseMessage, mismatches)
	}
}

func handleRequest(req string, conn net.Conn, expectedMessage string, response string, mismatchesMap map[string]*plugin.ContentMismatches) {
	log.Println("[INFO] server received request", req, "on connection", conn)

	mismatches := make([]*plugin.ContentMismatch, 0)

	if !isValidMessage(req) {
		log.Println("[DEBUG] server received invalid request, erroring")

		mismatches = append(mismatches, &plugin.ContentMismatch{
			Path:     "$",
			Mismatch: fmt.Sprintf("Received invalid request '%s', message is not a valid MATT message", req),
		})

		conn.Write([]byte("ERROR\n"))
	}
	log.Println("[DEBUG] server received valid request, responding")

	parsed := parseMattMessage(req)

	log.Println("[DEBUG] parsed message", parsed)

	if parsed != expectedMessage {
		log.Println("[DEBUG] matching error", parsed, "!=", expectedMessage)
		mismatches = append(mismatches, &plugin.ContentMismatch{
			Path:     "$",
			Mismatch: fmt.Sprintf("Expected '%s', but received '%s'", expectedMessage, parsed),
			Expected: wrapperspb.Bytes([]byte(expectedMessage)),
			Actual:   wrapperspb.Bytes([]byte(parsed)),
		})
		log.Println("[DEBUG] mismatches", mismatches)
	}

	conn.Write([]byte(generateMattMessage(response)))
	conn.Write([]byte("\n"))

	log.Println("[DEBUG] updating mismatchesMap")
	if len(mismatches) > 0 {
		mismatchesMap["$"] = &plugin.ContentMismatches{
			Mismatches: mismatches,
		}
	}
}

func callMattServiceTCP(host string, port int, message string) (string, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return "", err
	}

	conn.Write([]byte(generateMattMessage(message)))
	conn.Write([]byte("\n"))

	str, err := bufio.NewReader(conn).ReadString('\n')
	log.Println("[DEBUG] received raw message:", str, err)

	if err != nil {
		return "", err
	}

	return parseMattMessage(str), nil
}
