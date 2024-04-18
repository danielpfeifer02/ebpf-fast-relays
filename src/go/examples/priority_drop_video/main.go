package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
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

	mainConfig()
	os.Remove("tls.keylog")

	args := os.Args
	if len(args) != 2 {
		fmt.Println("Usage: go run *.go (server|client|relay)")
		return
	}

	if args[1] == "server" {

		video_main(args[1])

		// serverConfig()

		// scanner := bufio.NewScanner(os.Stdin)

		// server := NewStreamingServer()
		// go server.run()

		// for {
		// 	clearScreen()
		// 	printMenuServer()

		// 	fmt.Print("Choose an action: ")
		// 	if !scanner.Scan() {
		// 		fmt.Println("Error reading input:", scanner.Err())
		// 		return
		// 	}
		// 	choiceStr := scanner.Text()
		// 	choice, err := strconv.Atoi(choiceStr)
		// 	if err != nil {
		// 		fmt.Println("Invalid choice. Please enter a number.")
		// 		time.Sleep(sleeping_time)
		// 		continue
		// 	}

		// 	switch choice {
		// 	case 1:
		// 		fmt.Println("Sending high-prio message to all clients via streams")
		// 		server.sendToAll("foobar high\n", priority_setting.HighPriority, USE_STREAMS)
		// 		time.Sleep(sleeping_time)
		// 	case 2:
		// 		fmt.Println("Sending low-prio message to all clients via streams")
		// 		server.sendToAll("foobar low\n", priority_setting.LowPriority, USE_STREAMS)
		// 		time.Sleep(sleeping_time)
		// 	case 3:
		// 		fmt.Println("Sending high-prio message to all clients via datagrams")
		// 		server.sendToAll("foobar high\n", priority_setting.HighPriority, USE_DATAGRAMS)
		// 		time.Sleep(sleeping_time)
		// 	case 4:
		// 		fmt.Println("Sending low-prio message to all clients via datagrams")
		// 		server.sendToAll("foobar low\n", priority_setting.LowPriority, USE_DATAGRAMS)
		// 		time.Sleep(sleeping_time)
		// 	case 5:
		// 		fmt.Println("Changing priority drop threshold")
		// 		time.Sleep(sleeping_time)
		// 	case 6:
		// 		fmt.Println("Exiting")
		// 		server.interrupt_chan <- true
		// 		time.Sleep(sleeping_time)
		// 		return
		// 	default:
		// 		clearScreen()
		// 		printMenuServer()
		// 	}

		// }

	} else if args[1] == "client" {

		// clientConfig()

		video_main(args[1])

		// clearScreen()

		// client := NewStreamingClient()
		// client.connectToServer()
		// client.run()

	} else if args[1] == "relay" {

		video_main(args[1])

		// relayConfig()

		// relay := NewRelayServer()
		// go relay.run()

		// for {
		// 	if len(relay.client_list) > 0 {
		// 		break
		// 	}
		// }

		// for {

		// 	clearScreen()
		// 	printMenuRelay()

		// 	scanner := bufio.NewScanner(os.Stdin)
		// 	fmt.Print("Choose an action: ")
		// 	if !scanner.Scan() {
		// 		fmt.Println("Error reading input:", scanner.Err())
		// 		return
		// 	}
		// 	choiceStr := scanner.Text()
		// 	choice, err := strconv.Atoi(choiceStr)
		// 	if err != nil {
		// 		fmt.Println("Invalid choice. Please enter a number.")
		// 		time.Sleep(sleeping_time)
		// 		continue
		// 	}

		// 	switch choice {
		// 	case 1:
		// 		fmt.Println("Changing priority drop threshold")
		// 		relay.changePriorityDropThreshold()
		// 		time.Sleep(sleeping_time)
		// 	case 2:
		// 		fmt.Println("Exiting")
		// 		relay.interrupt_chan <- true
		// 		time.Sleep(sleeping_time)
		// 		return
		// 	default:
		// 		clearScreen()
		// 		printMenuRelay()
		// 	}
		// }

	} else {

		fmt.Printf("Usage: go run %s (server|client|relay)\n", args[0])

	}

}
