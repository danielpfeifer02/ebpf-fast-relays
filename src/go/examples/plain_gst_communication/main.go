package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"os"

	"common.com/common"
	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/go-gst/go-gst/gst"
)

// Sepcifications for a sender of video data.
var sender_specs = common.Sender_spec_struct{
	// The filepath of the video file that should be sent.
	FilePath: "../../../video/example.mp4",
	// The maximum interval between key-frames (i-frames) in the video.
	KeyFrameMaxDist: 2,
	// The minimum interval between key-frames (i-frames) in the video.
	KeyFrameMinDist: 0,
}

const SERVER_ADDR string = "192.168.10.1:4242"

func main() {
	// crypto_turnoff.CRYPTO_TURNED_OFF = true
	main_video()
}

func main_video() {

	gst.Init(nil)
	// defer gst.Deinit() // TODO: why C^ not working with this on?

	arguemnts := os.Args
	if len(arguemnts) != 2 {
		fmt.Println("Usage: go run *.go (server|client) [1]")
		return
	}

	if arguemnts[1] == "server" {
		server_start_video()
	} else if arguemnts[1] == "relay" {
		client_start_video()
	} else {
		fmt.Println("Usage: go run *.go (server|client) [2]")
	}
}

func server_start_video() {
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	done := common.StartSignalHandler()

	go func(ctx context.Context) {
		sender, err := newSender(ctx, SERVER_ADDR)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Starting sender")
		sender.start()
		<-ctx.Done()
		err = sender.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(ctx)

	<-done
}

func client_start_video() {
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	done := common.StartSignalHandler()

	go func() {
		receiver, err := newReceiver(ctx, SERVER_ADDR)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Starting receiver")
		receiver.start()
		<-ctx.Done()
		err = receiver.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	<-done
}

func generateTLSConfig(generate_keylog bool) *tls.Config {
	return common.GenerateTLSConfig(common.TLSConfigOptions{
		InsecureSkipVerify: true,
		EnableKeyLog:       generate_keylog,
		KeyLogPerm:         0777,
		PrintKeyLogCreated: true,
	})
}

func generateQUICConfig() *quic.Config {
	return &quic.Config{
		Allow0RTT:               false,
		DisablePathMTUDiscovery: true,
		EnableDatagrams:         true,
	}
}

func handleMessage(msg *gst.Message) error {
	return common.HandleGstMessage(msg)
}
