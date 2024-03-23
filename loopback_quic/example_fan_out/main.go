package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"github.com/danielpfeifer02/quic-go-prio-packs/crypto_turnoff"
)

const sleeping_time = 1 * time.Second

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

func printMenu() {
	fmt.Println("Menu:")
	fmt.Println("1. Send a message to all clients")
	fmt.Println("2. Exit")
}

func main() {
	main_advanced()
}

func main_advanced() {

	crypto_turnoff.CRYPTO_TURNED_OFF = true

	args := os.Args
	if len(args) != 2 {
		fmt.Printf("Usage: go run *.go (server|client)\n", args[0])
		return
	}

	if args[1] == "server" {

		crypto_turnoff.CRYPTO_TURNED_OFF = true

		scanner := bufio.NewScanner(os.Stdin)

		server := NewStreamingServer()
		relay := NewRelayServer()

		go server.run()
		go relay.run()

		for {
			clearScreen()
			printMenu()

			fmt.Print("Choose an action: ")
			if !scanner.Scan() {
				fmt.Println("Error reading input:", scanner.Err())
				return
			}
			choiceStr := scanner.Text()
			choice, err := strconv.Atoi(choiceStr)
			if err != nil {
				fmt.Println("Invalid choice. Please enter a number.")
				time.Sleep(sleeping_time)
				continue
			}

			switch choice {
			case 1:
				fmt.Println("Sending message to all clients")
				server.sendToAll("foobar")
				time.Sleep(sleeping_time)
			case 2:
				fmt.Println("Exiting")
				server.interrupt_chan <- true
				time.Sleep(sleeping_time)
				return
			default:
				clearScreen()
				printMenu()
			}

		}

	} else if args[1] == "client" {

		clearScreen()

		client := NewStreamingClient()
		client.connectToServer()
		client.run()

		// } else if args[1] == "relay" {

		// 	relay := NewRelayServer()
		// 	relay.run()

	} else {

		fmt.Printf("Usage: go run %s (server|client)\n", args[0])

	}

}

func main_basic() {

	server := NewStreamingServer()
	go server.run()
	time.Sleep(sleeping_time)

	client := NewStreamingClient()
	go client.run()
	time.Sleep(sleeping_time)

	client.connectToServer()
	time.Sleep(sleeping_time)

	server.sendToAll("Hello, World!")
	time.Sleep(sleeping_time)

	fmt.Println("Sending interrupt")
	server.interrupt_chan <- true
	time.Sleep(sleeping_time)

	fmt.Println("Done")
}
