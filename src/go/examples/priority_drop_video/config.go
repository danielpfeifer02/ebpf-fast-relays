package main

import (
	"log"
	"os"
	"time"

	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/danielpfeifer02/quic-go-prio-packs/crypto_turnoff"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
	"github.com/danielpfeifer02/quic-go-prio-packs/qlog"
)

const bpf_enabled = true
const relay_passing_on = false //true
const relay_playing = false
const relay_caching = true
const relay_printing_rtt = false
const DEBUG_PRINT = false

func generateQUICConfig() *quic.Config {
	return &quic.Config{
		Tracer:                 qlog.DefaultTracer,
		MaxIdleTimeout:         5 * time.Minute,
		EnableDatagrams:        true,
		MaxStreamReceiveWindow: 1 << 30,
	}
}

func mainConfig() {
	crypto_turnoff.CRYPTO_TURNED_OFF = true
	packet_setting.ALLOW_SETTING_PN = true
	packet_setting.EXCHANGE_PRIOS = false
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
	packet_setting.IS_CLIENT = false
}

func relayConfig() {
	// // We only want these functions to be executed in the relay
	if bpf_enabled {
		packet_setting.ConnectionInitiationBPFHandler = initConnectionId
		packet_setting.ConnectionRetirementBPFHandler = retireConnectionId
		packet_setting.ConnectionUpdateBPFHandler = updateConnectionId
		// 	// packet_setting.PacketNumberIncrementBPFHandler = incrementPacketNumber // TODO: still needed?
		packet_setting.AckTranslationBPFHandler = translateAckPacketNumber
		packet_setting.AckTranslationDeletionBPFHandler = deleteAckPacketNumberTranslation
		packet_setting.SET_ONLY_APP_DATA = true // TODO: fix in prio_packs repo?
	}
	packet_setting.IS_CLIENT = false
}

func clientConfig() {
	os.Setenv("QLOGDIR", "./qlog")
	packet_setting.PRINT_PACKET_RECEIVING_INFO = false
	packet_setting.IS_CLIENT = true
}

// // Setup a bare-bones TLS config for the server
// func generateTLSConfig(klf bool) *tls.Config {
// 	key, err := rsa.GenerateKey(rand.Reader, 1024)
// 	if err != nil {
// 		panic(err)
// 	}
// 	template := x509.Certificate{SerialNumber: big.NewInt(1)}
// 	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
// 	if err != nil {
// 		panic(err)
// 	}
// 	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
// 	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

// 	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
// 	if err != nil {
// 		panic(err)
// 	}

// 	if !klf {
// 		return &tls.Config{
// 			Certificates: []tls.Certificate{tlsCert},
// 			NextProtos:   []string{"quic-streaming-example"},
// 			CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256},
// 		}
// 	}

// 	// Create a KeyLogWriter
// 	keyLogFile, err := os.OpenFile("tls.keylog", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
// 	if err != nil {
// 		panic(err)
// 	}
// 	// defer keyLogFile.Close() // TODO why not close?

// 	return &tls.Config{
// 		Certificates: []tls.Certificate{tlsCert},
// 		NextProtos:   []string{"quic-streaming-example"},
// 		KeyLogWriter: keyLogFile,
// 		CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256},
// 	}
// }
