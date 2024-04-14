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
	"github.com/danielpfeifer02/quic-go-prio-packs/priority_setting"
)

const sleeping_time = 1 * time.Second
const USE_STREAMS = false
const USE_DATAGRAMS = true

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

func printMenuServer() {
	fmt.Println("Menu:")
	fmt.Println("1. Send a high-prio message to all clients via stream")
	fmt.Println("2. Send a low-prio message to all clients via stream")
	fmt.Println("3. Send a high-prio message to all clients via datagrams")
	fmt.Println("4. Send a low-prio message to all clients via datagrams")
	fmt.Println("5. Exit")
}

func printMenuRelay() {
	fmt.Println("Menu:")
	fmt.Println("1. Change priority drop threshold")
	fmt.Println("2. Exit")
}

func main() {
	main_advanced()
}

// TODO: fix timeout issues when there is no stuff happening

func main_advanced() {

	crypto_turnoff.CRYPTO_TURNED_OFF = true
	packet_setting.ALLOW_SETTING_PN = true
	// packet_setting.OMIT_CONN_ID_RETIREMENT = true

	f, err := os.Create("./log.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err != nil {
		panic(err)
	}
	log.SetOutput(f)
	// os.Setenv("QUIC_GO_LOG_LEVEL", "DEBUG") // TODO: not working

	// os.Setenv("QLOGDIR", "./qlog")
	os.Remove("tls.keylog")

	args := os.Args
	if len(args) != 2 {

		//TODO remove first case
		if len(args) == 3 && args[1] == "relay" {
			bpf_enabled = false
		} else {
			fmt.Println("Usage: go run *.go (server|client|relay)")
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
			printMenuServer()

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
				fmt.Println("Sending high-prio message to all clients via streams")
				server.sendToAll("foobar high\n", priority_setting.HighPriority, USE_STREAMS)
				time.Sleep(sleeping_time)
			case 2:
				fmt.Println("Sending low-prio message to all clients via streams")
				server.sendToAll("foobar low\n", priority_setting.LowPriority, USE_STREAMS)
				time.Sleep(sleeping_time)
			case 3:
				fmt.Println("Sending high-prio message to all clients via datagrams")
				server.sendToAll("foobar high\n", priority_setting.HighPriority, USE_DATAGRAMS)
				time.Sleep(sleeping_time)
			case 4:
				fmt.Println("Sending low-prio message to all clients via datagrams")
				server.sendToAll("foobar low\n", priority_setting.LowPriority, USE_DATAGRAMS)
				time.Sleep(sleeping_time)
			case 5:
				fmt.Println("Changing priority drop threshold")
				time.Sleep(sleeping_time)
			case 6:
				fmt.Println("Exiting")
				server.interrupt_chan <- true
				time.Sleep(sleeping_time)
				return
			default:
				clearScreen()
				printMenuServer()
			}

		}

	} else if args[1] == "client" {
		os.Setenv("QLOGDIR", "./qlog")
		// packet_setting.PRINT_PACKET_RECEIVING_INFO = true

		clearScreen()

		client := NewStreamingClient()
		client.connectToServer()
		client.run()

	} else if args[1] == "relay" {

		// TODO: better set here or in server.go?
		// We only want these functions to be executed in the relay
		packet_setting.ConnectionInitiationBPFHandler = initConnectionId
		packet_setting.ConnectionRetirementBPFHandler = retireConnectionId
		packet_setting.ConnectionUpdateBPFHandler = updateConnectionId
		// packet_setting.PacketNumberIncrementBPFHandler = incrementPacketNumber // TODO: still needed?
		packet_setting.AckTranslationBPFHandler = translateAckPacketNumber
		packet_setting.SET_ONLY_APP_DATA = true // TODO: fix in prio_packs repo?

		relay := NewRelayServer()
		go relay.run()

		for {
			if len(relay.client_list) > 0 {
				break
			}
		}

		for {

			clearScreen()
			printMenuRelay()

			scanner := bufio.NewScanner(os.Stdin)
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
				fmt.Println("Changing priority drop threshold")
				relay.changePriorityDropThreshold()
				time.Sleep(sleeping_time)
			case 2:
				fmt.Println("Exiting")
				relay.interrupt_chan <- true
				time.Sleep(sleeping_time)
				return
			default:
				clearScreen()
				printMenuRelay()
			}
		}

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

	server.sendToAll("Hello, World!", priority_setting.HighPriority, true)
	time.Sleep(sleeping_time)

	fmt.Println("Sending interrupt")
	server.interrupt_chan <- true
	time.Sleep(sleeping_time)

	fmt.Println("Done")
}
