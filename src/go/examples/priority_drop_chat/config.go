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

// Setup a bare-bones TLS config for the server
func generateTLSConfig(klf bool) *tls.Config {
	return common.GenerateTLSConfig(common.TLSConfigOptions{
		NextProtos:   []string{"quic-streaming-example"},
		EnableKeyLog: klf,
		KeyLogPerm:   0600,
	})
}

func generateQUICConfig() *quic.Config {
	return &quic.Config{
		Tracer:          qlog.DefaultTracer,
		MaxIdleTimeout:  5 * time.Minute,
		EnableDatagrams: true,
	}
}

func mainConfig() {
	crypto_turnoff.CRYPTO_TURNED_OFF = true
	packet_setting.ALLOW_SETTING_PN = true
	// packet_setting.OMIT_CONN_ID_RETIREMENT = true

	f, err := os.Create("./build/log.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	log.SetOutput(f)
	// os.Setenv("QUIC_GO_LOG_LEVEL", "DEBUG") // TODO: not working

	// os.Setenv("QLOGDIR", "./qlog")
}

func serverConfig() {
	crypto_turnoff.CRYPTO_TURNED_OFF = true
}

func relayConfig() {
	// We only want these functions to be executed in the relay
	packet_setting.ConnectionInitiationBPFHandler = initConnectionId
	packet_setting.ConnectionRetirementBPFHandler = retireConnectionId
	packet_setting.ConnectionUpdateBPFHandler = updateConnectionId
	// packet_setting.PacketNumberIncrementBPFHandler = incrementPacketNumber // TODO: still needed?
	packet_setting.AckTranslationBPFHandler = translateAckPacketNumber
	packet_setting.SET_ONLY_APP_DATA = true // TODO: fix in prio_packs repo?
}

func clientConfig() {
	os.Setenv("QLOGDIR", "./qlog")
	packet_setting.PRINT_PACKET_RECEIVING_INFO = false
}
