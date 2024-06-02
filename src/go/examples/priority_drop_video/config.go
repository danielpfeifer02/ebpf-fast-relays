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

// If the bpf program is not enabled, the relay should not try to
// access the bpf maps as this would lead to a panic.
// Therefore this tells the relay if maps are available.
const bpf_enabled = true

// Specify if the relay should manually (from userspace) pass on packets
// that it receives from the server to the client(s).
// This is mainly used for development purposes.
const relay_passing_on = false

// Specify if the relay should play the video that it receives from the server.
// This is mainly used for development purposes.
const relay_playing = false

// Specify if the relay should cache the video that it receives from the server.
// Caching for relays is mentioned in this standard in section "1.1.4 Relays":
// https://datatracker.ietf.org/doc/draft-ietf-moq-transport/
// This is not yet completely implemented.
const relay_caching = false // TODO: causes protocol violation

// Specify number of packets being cached at most
const cache_packet_size = 1024

// Specify if the relay should print the round trip time information of the
// connections it manages.
// This will be the data on which the relay will base its decision to
// drop packets / adapt streaming rates to the client(s).
const relay_printing_rtt = true

// Specify wether the default test video should be played by the server
// or if an actual video file should be played.
const test_video = false

// Specify if any prints related to debugging should be printed.
const DEBUG_PRINT = false

// Specify if the relay should create a video config managing window
// which allows for easier debugging / changing of the video settings.
const video_config_window = true

// Sepcifications for a sender of video data.
var sender_specs = sender_spec_struct{
	// The filepath of the video file that should be sent.
	FilePath: "../../../video/example.mp4",
	// The maximum interval between key-frames (i-frames) in the video.
	KeyFrameMaxDist: 2,
	// The minimum interval between key-frames (i-frames) in the video.
	KeyFrameMinDist: 0,
}

// Specifying if the server application should allow the user to change the
// sender spcifications.
const server_changing_sender_specs = true

// Specifying if the relay application should allow the user to change the
// sender spcifications.
const relay_changing_sender_specs = false

// Specifying the minimum choosable value for the packet priority.
// This is just for the debugging manager.
const min_priority_slider = 0

// Specifying the maximum choosable value for the packet priority.
// This is just for the debugging manager.
const max_priority_slider = 3

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

func relayConfig() {

	if bpf_enabled {

		// TODO: check if those three functions are correctly implemented
		packet_setting.ConnectionInitiationBPFHandler = initConnectionId
		packet_setting.ConnectionRetirementBPFHandler = retireConnectionId
		packet_setting.ConnectionUpdateBPFHandler = updateConnectionId

		// This is for the packet number translation
		packet_setting.AckTranslationBPFHandler = translateAckPacketNumber
		packet_setting.AckTranslationDeletionBPFHandler = deleteAckPacketNumberTranslation

		// TODO: fix in prio_packs repo?
		packet_setting.SET_ONLY_APP_DATA = true

		// Set the registration of BPF packets to on
		packet_setting.BPF_PACKET_REGISTRATION = true
	}

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
