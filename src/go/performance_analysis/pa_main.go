package main

import (
	"fmt"
	"os"
)

func main() {

	args := os.Args
	if len(args) != 3 {
		fmt.Println("Usage: go run *.go (cpu|diff) (server|client|relay)")
		return
	}

	generalConfig()

	if args[2] == "server" {

		serverConfig()

		if args[1] == "cpu" {
			number_of_analysis_packets = CPU_TEST_PACKET_NUMBER
			analyse_diff_data = false
			server_latency_diff() // TODO: something else needed than just longer execution?
		} else if args[1] == "diff" {
			analyse_diff_data = true
			server_latency_diff()
		} else {
			fmt.Println("Usage: go run *.go (cpu|diff) (server|client|relay)")
		}

	} else if args[2] == "client" {

		clientConfig()

		if args[1] == "cpu" {
			number_of_analysis_packets = CPU_TEST_PACKET_NUMBER
			analyse_diff_data = false
			client_latency_diff() // TODO: something else needed than just longer execution?
		} else if args[1] == "diff" {
			analyse_diff_data = true
			client_latency_diff()
		} else {
			fmt.Println("Usage: go run *.go (cpu|diff) (server|client|relay)")
		}

	} else if args[2] == "relay" {

		relayConfig()
		relay()

	} else {
		fmt.Println("Usage: go run *.go (server|client|relay)")
	}

}
