package main

func main() {
	initLogging()

	// Start the Plugin Server
	// TODO: proper handling of startup/shutdown
	startPluginServer(serverDetails{
		Port:      64261,
		ServerKey: "f9b02850-5c5a-4cf0-a500-3dc7e74e3854",
	})
}
