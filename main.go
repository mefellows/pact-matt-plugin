package main

import (
	"fmt"
	"log"

	"github.com/google/uuid"
)

func main() {
	defer handlePanic()

	initLogging()

	port, err := GetFreePort()
	if err != nil {
		log.Fatal("ERROR unable to find a free port:", err)
	}

	// Start the Plugin Server
	// TODO: proper handling of startup/shutdown
	startPluginServer(serverDetails{
		Port:      port,
		ServerKey: uuid.NewString(),
	})
}

func handlePanic() {
	if r := recover(); r != nil {
		l := len(fmt.Sprintf("recovered from panic: %v", r))
		stars := make([]byte, l)
		for i := 0; i < l; i++ {
			stars[i] = '*'
		}
		log.Println("[ERROR]", string(stars))
		log.Println("[ERROR] recovered from panic:", r)
		log.Println("[ERROR]", string(stars))
	}
}
