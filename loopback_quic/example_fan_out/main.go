package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"github.com/danielpfeifer02/quic-go-prio-packs/crypto_turnoff"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
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
	fmt.Println("1. Send a high-prio message to all clients")
	fmt.Println("2. Send a low-prio message to all clients")
	fmt.Println("3. Exit")
}

func main() {
	main_advanced()
}

// TODO: fix timeout issues when there is no stuff happening

func main_advanced() {

	crypto_turnoff.CRYPTO_TURNED_OFF = true
	packet_setting.ALLOW_SETTING_PN = true

	f, err := os.Create("./log.txt")
	defer f.Close()
	if err != nil {
		panic(err)
	}
	log.SetOutput(f)
	// os.Setenv("QUIC_GO_LOG_LEVEL", "DEBUG") // TODO: not working

	os.Setenv("QLOGDIR", "./qlog")
	os.Remove("tls.keylog")

	args := os.Args
	if len(args) != 2 {

		//TODO remove first case
		if len(args) == 3 && args[1] == "relay" {
			bpf_enabled = false
		} else {
			fmt.Printf("Usage: go run *.go (server|client|relay)\n", args[0])
			return
		}
	}

	if args[1] == "server" {

		crypto_turnoff.CRYPTO_TURNED_OFF = true

		scanner := bufio.NewScanner(os.Stdin)

		server := NewStreamingServer()

		go server.run()

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
				fmt.Println("Sending high-prio message to all clients")
				server.sendToAllHigh("foobar high")
				time.Sleep(sleeping_time)
			case 2:
				fmt.Println("Sending low-prio message to all clients")
				server.sendToAllLow("foobar low")
				time.Sleep(sleeping_time)
			case 3:
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

	} else if args[1] == "relay" {

		clearScreen()

		relay := NewRelayServer()
		relay.run()

	} else {

		fmt.Printf("Usage: go run %s (server|client|relay)\n", args[0])

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

	server.sendToAllHigh("Hello, World!")
	time.Sleep(sleeping_time)

	fmt.Println("Sending interrupt")
	server.interrupt_chan <- true
	time.Sleep(sleeping_time)

	fmt.Println("Done")
}
