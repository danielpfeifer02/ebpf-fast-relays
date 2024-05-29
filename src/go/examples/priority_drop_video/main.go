package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/go-gst/go-gst/gst"
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

	for i := 0; i < 20; i++ {
		fmt.Println("Don't forget also sending on low priority streams! (func (s *objectStream) Write(payload []byte) (int, error))")
		fmt.Print("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n")
	}

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

// TODO:
// REMOVE
// REMOVE
func main_testing() {
	fmt.Println("Starting...")
	server := flag.Bool("server", false, "Run as server and send media (true) or run as client and receive media (false)")
	addr := flag.String("addr", video_server_address, "address")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	done := make(chan struct{}, 1)

	go func() {
		if err := run(ctx, *server, *addr); err != nil {
			log.Fatal(err)
		}
	}()

	<-done
}

func run(ctx context.Context, server bool, addr string) error {
	gst.Init(nil)
	defer gst.Deinit()

	if server {
		s, err := newSender(ctx, addr)
		if err != nil {
			return err
		}
		s.start()
		<-ctx.Done()
		return s.Close()
	}
	r, err := newReceiver(ctx, addr)
	if err != nil {
		return err
	}
	r.start()
	<-ctx.Done()
	return r.Close()
}
