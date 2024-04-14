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

const adaptiveFlagMapPath = "/sys/fs/bpf/adaptive_flag"

func printMenu() {
	fmt.Println("Menu:")
	fmt.Println("1. Enable Adaptive Priority Control (APC)")
	fmt.Println("2. Disable Adaptive Priority Control (APC)")
	fmt.Println("3. Run example QUIC traffic")
	fmt.Println("4. Toggle crypto turn off")
	fmt.Println("5. Exit")
}

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

func setAPC(value string) {
	// TODO get error opening BPF map? used to work?
	cmd := exec.Command("../manage/apc_set", "-p", adaptiveFlagMapPath, "-v", value)
	cmd.Stdout = os.Stdout
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error setting APC:", err)
	}
}

func main() {

	on := "1"
	off := "0"

	scanner := bufio.NewScanner(os.Stdin)
	clearScreen()
	fmt.Print("\n\n\n")
	printMenu()
	fmt.Print("\n (don't forget to make targets \"ingress\" and \"manage\" first, in said order)\n\n")

	for {

		fmt.Print("Choose an action: ")
		if !scanner.Scan() {
			fmt.Println("Error reading input:", scanner.Err())
			return
		}
		choiceStr := scanner.Text()
		choice, err := strconv.Atoi(choiceStr)
		if err != nil {
			fmt.Println("Invalid choice. Please enter a number.")
			continue
		}

		switch choice {
		case 1:
			clearScreen()
			fmt.Print("\nEnabling APC...\n\n")
			fmt.Print("========================\n\n")
			setAPC(on)
			fmt.Print("\n========================\n\n")
			printMenu()
		case 2:
			clearScreen()
			fmt.Print("\nDisabling APC...\n\n")
			fmt.Print("========================\n\n")
			setAPC(off)
			fmt.Print("\n========================\n\n")
			printMenu()
		case 3:
			clearScreen()
			fmt.Print("\nRunning example traffic...\n\n")
			fmt.Print("========================\n\n")
			createTraffic(5)
			fmt.Print("========================\n\n")
			printMenu()
		case 4:
			clearScreen()
			fmt.Print("\n\n\n")
			// turn off crypto
			crypto_turnoff.CRYPTO_TURNED_OFF = !crypto_turnoff.CRYPTO_TURNED_OFF
			fmt.Println("Crypto turned off:", crypto_turnoff.CRYPTO_TURNED_OFF)
			fmt.Print("\n\n\n")
			printMenu()
		case 5:
			clearScreen()
			fmt.Print("\nExiting...\n\n")
			time.Sleep(1 * time.Second)
			clearScreen()
			return
		default:
			clearScreen()
			printMenu()
			fmt.Println("\nInvalid choice. Please choose a number between 1 and 5.")
		}
	}
}

/*
func getMapFD(mapName string) (uint32, error) {
	tmp := exec.Command("whoami")
	out, err := tmp.Output()
	fmt.Print("User: ", string(out))
	// Run bpftool map show command to retrieve information about the BPF map
	cmd := exec.Command("bpftool", "map", "show", "name", mapName)
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	print("Output: ", string(output))

	// Parse the output to extract the file descriptor of the BPF map
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "fd:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				fdStr := strings.TrimSpace(parts[1])
				fd, err := strconv.ParseUint(fdStr, 10, 32)
				if err != nil {
					return 0, err
				}
				return uint32(fd), nil
			}
		}
	}

	return 0, fmt.Errorf("file descriptor not found for BPF map %s", mapName)
}
*/
