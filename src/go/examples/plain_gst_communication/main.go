package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"

	"common.com/common"
	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/go-gst/go-gst/gst"
	"github.com/go-gst/go-gst/gst/app"
	// "github.com/quic-go/quic-go"
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
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	if !generate_keylog {
		return &tls.Config{
			Certificates:       []tls.Certificate{tlsCert},
			InsecureSkipVerify: true,
			CipherSuites:       []uint16{tls.TLS_CHACHA20_POLY1305_SHA256},
		}
	}

	// Keylog file
	keylogFile, err := os.OpenFile("tls.keylog", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		panic(err)
	}

	fmt.Println("TLS keylog file created")

	return &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: true,
		KeyLogWriter:       keylogFile,
		CipherSuites:       []uint16{tls.TLS_CHACHA20_POLY1305_SHA256},
	}
}

func generateQUICConfig() *quic.Config {
	return &quic.Config{
		Allow0RTT:               false,
		DisablePathMTUDiscovery: true,
		EnableDatagrams:         true,
	}
}

func handleMessage(msg *gst.Message) error {
	switch msg.Type() {
	case gst.MessageEOS:
		return app.ErrEOS
	case gst.MessageError:
		return msg.ParseError()
	}
	return nil
}
