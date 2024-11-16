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

	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/danielpfeifer02/quic-go-prio-packs/crypto_turnoff"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
)

func main() {

	crypto_turnoff.CRYPTO_TURNED_OFF = false
	crypto_turnoff.HEADER_PROTECTION_TURNED_OFF = true

	arguemnts := os.Args
	if len(arguemnts) != 2 {
		fmt.Println("Usage: go run *.go (server|client) [1]")
		return
	}

	if arguemnts[1] == "server" {
		startServer()
	} else if arguemnts[1] == "relay" {
		// crypto_turnoff.CRYPTO_TURNED_OFF = true // TODO: this will show that the relay is able to decrypt the packet
		err := startClient()
		if err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Println("Usage: go run *.go (server|client) [2]")
	}
}

func startServer() {
	listener, err := quic.ListenAddr(packet_setting.SERVER_ADDR, generateTLSConfig(), getQUICConfig())
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
	stream, err := sess.AcceptStream(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer stream.Close()

	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil {
		fmt.Println("Error reading from stream (server)")
		log.Fatal(err)
	}
	fmt.Printf("Server: Got '%s'\n", string(buf[:n]))

	_, err = stream.Write([]byte("Hello from server"))
	if err != nil {
		fmt.Println("Error writing to stream (server)")
		log.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // Wait before closing the stream
}

func startClient() error {
	tlsConf := &tls.Config{InsecureSkipVerify: true}
	session, err := quic.DialAddr(context.Background(), packet_setting.SERVER_ADDR, tlsConf, getQUICConfig())
	if err != nil {
		return err
	}
	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}
	defer stream.Close()

	_, err = stream.Write([]byte("Hello from client"))
	if err != nil {
		fmt.Println("Error writing to stream (client)")
		return err
	}

	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil {
		fmt.Println("Error reading from stream (client)")
		return err
	}
	fmt.Printf("Client: Got '%s'\n", string(buf[:n]))
	return nil
}

func generateTLSConfig() *tls.Config {
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

func getQUICConfig() *quic.Config {
	return &quic.Config{}
}