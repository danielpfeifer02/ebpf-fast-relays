package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"

	"common.com/common"
	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/danielpfeifer02/quic-go-prio-packs/crypto_turnoff"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
	"github.com/danielpfeifer02/quic-go-prio-packs/qlog"
)

const (
	local_usage            = false
	use_datagrams          = false
	bpf_enabled            = true //!local_usage
	forwarding_enabled     = true //!bpf_enabled
	count_errors           = true
	payload_length         = 21 //512
	USERSPACE_FLAG         = 0b10000000
	CPU_TEST_PACKET_NUMBER = 1 << 20
)

var (
	server_addr = map[bool]string{true: "localhost:4242", false: "192.168.10.1:4242"}[local_usage]
	// client_addr = map[bool]string{true: "localhost:4243", false: "192.168.11.1:4242"}[local_usage]
	relay_addr = map[bool]string{true: "localhost:4244", false: "192.168.11.2:4242"}[local_usage]

	// Needs to be var since cpu flag changes it
	number_of_analysis_packets = 1024
	analyse_diff_data          = false
)

func generalConfig() {
	crypto_turnoff.CRYPTO_TURNED_OFF = true
	packet_setting.ALLOW_SETTING_PN = true
}

func serverConfig() {}

func relayConfig() {
	packet_setting.IS_RELAY = true

	// os.Setenv("QLOGDIR", "./qlog")
}

func clientConfig() {
	packet_setting.IS_CLIENT = true

	os.Setenv("QLOGDIR", "./qlog")
}

func generatePAQuicConfig() *quic.Config {
	return &quic.Config{
		Tracer:                qlog.DefaultTracer,
		EnableDatagrams:       true,
		MaxIncomingStreams:    1 << 15,
		MaxIncomingUniStreams: 1 << 15,
	}
}

func generatePATLSConfig() *tls.Config {
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

	return &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: true,
		NextProtos:         []string{"moq-00"},
		CipherSuites:       []uint16{tls.TLS_CHACHA20_POLY1305_SHA256},
	}

}

func setBPFHandlers() {
	if bpf_enabled { // TODO: which ones are not necessary anymore?

		fmt.Println("Setting up BPF for relay")

		packet_setting.StoreServerPacket = common.StoreServerPacket
		packet_setting.StoreRelayPacket = common.StoreRelayPacket
		packet_setting.PacketOriginatedAtRelay = common.PacketOriginatedAtRelay

		// TODO: check if those three functions are correctly implemented
		packet_setting.ConnectionInitiationBPFHandler = common.InitConnectionId
		packet_setting.ConnectionRetirementBPFHandler = common.RetireConnectionId
		packet_setting.ConnectionUpdateBPFHandler = common.UpdateConnectionId // TODO: something seems to be wrong with this -> panic

		// This is for the packet number translation
		// packet_setting.AckTranslationBPFHandler = common.TranslateAckPacketNumber
		// packet_setting.AckTranslationDeletionBPFHandler = common.DeleteAckPacketNumberTranslation

		// This is to get the highest packet number of a connection that was sent
		packet_setting.ConnectionGetLargestSentPacketNumber = common.GetLargestSentPacketNumber

		packet_setting.MarkStreamIdAsRetransmission = common.MarkStreamIdAsRetransmission

		// TODO: fix in prio_packs repo?
		packet_setting.SET_ONLY_APP_DATA = true

		// Set the registration of BPF packets to on
		packet_setting.BPF_PACKET_REGISTRATION = true

	}
}
