package main

import (
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
	"github.com/danielpfeifer02/quic-go-prio-packs/qlog"
)

// Specify wether the default test video should be played by the server
// or if an actual video file should be played.
const test_video = false

// Specify if any prints related to debugging should be printed.
const DEBUG_PRINT = false

// This config is used for all three roles (server, relay, client)
func mainConfig() {

	// Specifyig that there is no en- or decryption
	// in the underlying QUIC implementation.
	crypto_turnoff.CRYPTO_TURNED_OFF = true

	// Specifying if the packet number of a connection can be
	// set from outside the underlying QUIC implementation.
	// This is not needed if the packet number translation from
	// within the bpf program is used.
	packet_setting.ALLOW_SETTING_PN = false

	// Specify if two end points should exchange the priority of a
	// created stream (i.e. if the server should send it to the client).
	// This is currently not working together with the bpf program.
	packet_setting.EXCHANGE_PRIOS = false

	// Specify if the connection id retirement should be omitted.
	packet_setting.OMIT_CONN_ID_RETIREMENT = false

	// Create a log file for the QUIC implementation
	f, err := os.Create("./build/log.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	log.SetOutput(f)
	// This currently seems to be not working
	// os.Setenv("QUIC_GO_LOG_LEVEL", "DEBUG")
}

func serverConfig() {
	// Specify if the calling program is the client to be able to access
	// this information in the underlying QUIC implementation.
	// This was mainly used for development purposes.
	// TODO: is this still used?
	packet_setting.IS_CLIENT = false
}

func clientConfig() {

	// Specify if the directory for the qlog files
	os.Setenv("QLOGDIR", "./qlog")

	// Specify if the underlying QUIC implementation should print
	// information on receiving packets (i.e. the packet number).
	// This was mainly used for development purposes.
	packet_setting.PRINT_PACKET_RECEIVING_INFO = false

	// Specify if the calling program is the client to be able to access
	// this information in the underlying QUIC implementation.
	// This was mainly used for development purposes.
	// TODO: is this still used?
	packet_setting.IS_CLIENT = true
}

// Setup basic QUIC config for server/relay/client
func generateQUICConfig() *quic.Config {
	return &quic.Config{
		Tracer:                     qlog.DefaultTracer,
		MaxIdleTimeout:             5 * time.Minute,
		EnableDatagrams:            true,
		MaxIncomingStreams:         1 << 60,
		MaxStreamReceiveWindow:     1 << 60,
		MaxIncomingUniStreams:      1 << 60,
		MaxConnectionReceiveWindow: 1 << 60,
	}
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig(klf bool) *tls.Config {
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

	if !klf {
		return &tls.Config{
			Certificates:       []tls.Certificate{tlsCert},
			InsecureSkipVerify: true,
			NextProtos:         []string{"moq-00"},
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
		NextProtos:         []string{"moq-00"},
		KeyLogWriter:       keylogFile,
		CipherSuites:       []uint16{tls.TLS_CHACHA20_POLY1305_SHA256},
	}
}
