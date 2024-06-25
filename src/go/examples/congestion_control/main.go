package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

func clearScreen() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		fmt.Print("\033[H\033[2J")
	}
}

// TODO: fix timeout issues when there is nothing happening
func main() {

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

	} else {

		fmt.Printf("Usage: go run %s (server|client|relay)\n", args[0])

	}

}
