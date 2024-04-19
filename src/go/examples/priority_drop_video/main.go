package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

func clearScreen() {
	// For Windows
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else { // For other systems (Linux, MacOS)
		fmt.Print("\033[H\033[2J")
	}
}

func main() {
	main_advanced()
}

// TODO: fix timeout issues when there is no stuff happening

func main_advanced() {

	mainConfig()
	os.Remove("tls.keylog")

	args := os.Args
	if len(args) != 2 {
		fmt.Println("Usage: go run *.go (server|client|relay)")
		return
	}

	if args[1] == "server" {

		serverConfig()
		clearScreen()
		video_main(args[1])

	} else if args[1] == "client" {

		clientConfig()
		clearScreen()
		video_main(args[1])

	} else if args[1] == "relay" {

		relayConfig()
		clearScreen()
		video_main(args[1])

	} else {

		fmt.Printf("Usage: go run %s (server|client|relay)\n", args[0])

	}

}
