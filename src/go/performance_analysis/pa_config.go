package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"

	"github.com/danielpfeifer02/quic-go-prio-packs"
)

var (
	server_addr   = "localhost:4242"
	client_addr   = "localhost:4243"
	relay_addr    = "localhost:4244"
	use_datagrams = false
	bpf_enabled   = true
)

func generalConfig() {
	// crypto_turnoff.CRYPTO_TURNED_OFF = true
}

func generatePAQuicConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:       true,
		MaxIncomingStreams:    100,
		MaxIncomingUniStreams: 100,
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
