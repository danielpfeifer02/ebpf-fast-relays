package main

import (
	"crypto/tls"
	"log"
	"os"
	"time"

	"common.com/common"
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
	return common.GenerateTLSConfig(common.TLSConfigOptions{
		NextProtos:         []string{"moq-00"},
		InsecureSkipVerify: true,
		EnableKeyLog:       klf,
		KeyLogPerm:         0777,
		PrintKeyLogCreated: true,
	})
}
