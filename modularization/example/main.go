package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"time"
)

func main() {
	intf := "veth0"
	ip := "192.168.1.2" // shouldnt matter
	numberOfPings := 5

	done := make(chan bool)
	go readFromTracingPipe(done)

	sendPings(intf, ip, numberOfPings)
	done <- true
}

func sendPings(intf string, ip string, count int) {
	cmd := exec.Command("ping", "-I", intf, "-c", fmt.Sprintf("%d", count), ip)
	cmd.Run()
}

func readFromTracingPipe(done chan bool) {
	pipePath := "/sys/kernel/tracing/trace_pipe"
	delimiter := "bpf_trace_printk: "
	delimiterBytes := []byte(delimiter)
	file, err := os.Open(pipePath)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer file.Close()

	buffer := make([]byte, 1024) // Adjust the buffer size as needed

	for {
		select {
		case <-done:
			return
		default:
			// Attempt to read from the named pipe with a timeout
			file.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) // Adjust timeout duration as needed
			n, err := file.Read(buffer)
			if err != nil {
				if os.IsTimeout(err) {
					// Timeout occurred, continue to the next iteration
					continue
				}
				fmt.Println("Error:", err)
				return
			}

			// If data is available, send it to the output channel
			if n > 0 {
				data := make([]byte, n)
				copy(data, buffer[:n])

				lines := bytes.Split(data, []byte("\n"))
				for _, line := range lines {
					if !bytes.Contains(line, delimiterBytes) {
						continue
					}
					line = bytes.Split(line, delimiterBytes)[1]
					fmt.Println(string(line))
				}
			}
		}
	}
}
