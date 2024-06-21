package main

import (
	"fmt"
	"os"
)

func main() {

	args := os.Args
	if len(args) != 2 {
		fmt.Println("Usage: go run *.go (server|client|relay)")
		return
	}

	generalConfig()

	if args[1] == "server" {

		server()

	} else if args[1] == "client" {

		client()

	} else if args[1] == "relay" {

		relay()

	} else {
		fmt.Println("Usage: go run *.go (server|client|relay)")
	}

}
