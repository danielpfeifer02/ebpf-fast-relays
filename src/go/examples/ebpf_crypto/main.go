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
	"time"

	"common.com/common"
	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/danielpfeifer02/quic-go-prio-packs/crypto_turnoff"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
	"github.com/danielpfeifer02/quic-go-prio-packs/qlog"
	"github.com/go-gst/go-gst/gst"
	"github.com/go-gst/go-gst/gst/app"

	crypto_settings "golang.org/x/crypto"
)

// ! TODO: turn off the header protection again
// ! TODO: set to correct states
const WHOLE_CRYPTO_TURNED_OFF = false
const HEADER_PROTECTION_TURNED_OFF = true
const INCOMING_SHORT_HEADER_CRYPTO_TURNED_OFF = true

const MSG_NUM = 10000
const MSG_SIZE = len("Hello from server xxxxx")

const MESSAGE_TEXT = 1 == 10

func main() {
	if MESSAGE_TEXT {
		main_message()
	} else {
		main_video()
	}
}

func main_video() {

	gst.Init(nil)
	// defer gst.Deinit() // TODO: why C^ not working with this on?

	crypto_turnoff.CRYPTO_TURNED_OFF = WHOLE_CRYPTO_TURNED_OFF
	crypto_turnoff.HEADER_PROTECTION_TURNED_OFF = HEADER_PROTECTION_TURNED_OFF

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
		sender, err := newSender(ctx, packet_setting.SERVER_ADDR)
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

	crypto_turnoff.INCOMING_SHORT_HEADER_CRYPTO_TURNED_OFF = INCOMING_SHORT_HEADER_CRYPTO_TURNED_OFF
	loadEBPFCryptoMaps()
	crypto_settings.EBPFXOrBitstreamRegister = eBPFXOrBitstreamRegister
	crypto_settings.PotentiallTriggerCryptoGarbageCollector = potentiallTriggerCryptoGarbageCollector
	crypto_settings.RegisterFullyReceivedPacket = registerFullyReceivedPacket

	done := common.StartSignalHandler()

	go func() {
		receiver, err := newReceiver(ctx, packet_setting.SERVER_ADDR)
		if err != nil {
			log.Fatal(err)
		}
		receiver.start()
		<-ctx.Done()
		err = receiver.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	<-done
}

func main_message() {

	crypto_turnoff.CRYPTO_TURNED_OFF = WHOLE_CRYPTO_TURNED_OFF
	crypto_turnoff.HEADER_PROTECTION_TURNED_OFF = HEADER_PROTECTION_TURNED_OFF

	arguemnts := os.Args
	if len(arguemnts) != 2 {
		fmt.Println("Usage: go run *.go (server|client) [1]")
		return
	}

	if arguemnts[1] == "server" {
		server_start_message()
	} else if arguemnts[1] == "relay" {
		// crypto_turnoff.CRYPTO_TURNED_OFF = true // TODO: this will show that the relay is able to decrypt the packet
		err := client_start_message()
		if err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Println("Usage: go run *.go (server|client) [2]")
	}
}

func server_start_message() {
	listener, err := quic.ListenAddr(packet_setting.SERVER_ADDR, generateTLSConfig(true), generateQUICConfig())
	if err != nil {
		log.Fatal(err)
	}
	sess, err := listener.Accept(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	handleSession(sess) // One session is enough for the poc
}

func handleSession(sess quic.Connection) {
	// stream, err := sess.OpenStreamSync(context.Background()) // TODO: change to AcceptStream if the code below is uncommented
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer stream.Close()

	// fmt.Println("Waiting for client to send a message")

	// buf := make([]byte, 1024)
	// n, err := stream.Read(buf)
	// if err != nil {
	// 	fmt.Println("Error reading from stream (server)")
	// 	log.Fatal(err)
	// }
	// fmt.Printf("Server: Got '%s'\n", string(buf[:n]))

	for i := 0; i < MSG_NUM; i++ {

		stream, err := sess.OpenStreamSync(context.Background()) // TODO: change to AcceptStream if the code below is uncommented
		if err != nil {
			log.Fatal(err)
		}
		defer stream.Close()

		_, err = stream.Write([]byte("Hello from server " + fmt.Sprintf("%05d", i)))
		if err != nil {
			fmt.Println("Error writing to stream (server)")
			log.Fatal(err)
		}
		fmt.Printf("Server: Sent 'Hello from server %d'\n", i)
		time.Sleep(time.Millisecond)

		// go func(stream quic.Stream) {
		// 	time.Sleep(100 * time.Millisecond) // Wait before closing the stream
		// 	stream.Close()
		// }(stream)
	}
	time.Sleep(100 * time.Millisecond) // Wait before closing the stream
}

func client_start_message() error {

	// Load the eBPF maps
	loadEBPFCryptoMaps()
	crypto_turnoff.INCOMING_SHORT_HEADER_CRYPTO_TURNED_OFF = INCOMING_SHORT_HEADER_CRYPTO_TURNED_OFF // TODO: this should be on since the ebpf prog is doing the decryption

	session, err := quic.DialAddr(context.Background(), packet_setting.SERVER_ADDR, generateTLSConfig(false), generateQUICConfig())
	if err != nil {
		return err
	}

	crypto_settings.EBPFXOrBitstreamRegister = eBPFXOrBitstreamRegister
	crypto_settings.PotentiallTriggerCryptoGarbageCollector = potentiallTriggerCryptoGarbageCollector
	crypto_settings.RegisterFullyReceivedPacket = registerFullyReceivedPacket

	go session.Start1RTTCryptoBitstreamStorage() // TODO: this call will be the core of the ebpf crypto handling
	time.Sleep(1 * time.Second)                  // TODO: necessary for preloading?

	// stream, err := session.AcceptStream(context.Background()) // TODO: change to OpenStreamSync if the code below is uncommented
	// if err != nil {
	// 	return err
	// }
	// defer stream.Close()

	// _, err = stream.Write([]byte("Hello from client"))
	// if err != nil {
	// 	fmt.Println("Error writing to stream (client)")
	// 	return err
	// }

	buf := make([]byte, MSG_SIZE)

	for i := 0; i < MSG_NUM; i++ {

		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			return err
		}
		defer stream.Close()

		n, err := stream.Read(buf)
		if err != nil {
			fmt.Println("Error reading from stream (client)")
			return err
		}
		fmt.Printf("Client: Got '%s'\n", string(buf[:n]))

		// go func(stream quic.Stream) {
		// 	time.Sleep(100 * time.Millisecond) // Wait before closing the stream
		// 	stream.Close()
		// }(stream)
	}
	return nil
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
		Tracer:                  qlog.DefaultTracer,
		Allow0RTT:               false,
		DisablePathMTUDiscovery: true,
		EnableDatagrams:         true,
		MaxIncomingStreams:      1 << 60,
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
