package common

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

// TLSConfigOptions parameterizes the shared self-signed TLS setup used by examples.
type TLSConfigOptions struct {
	NextProtos         []string
	InsecureSkipVerify bool
	EnableKeyLog       bool
	KeyLogPath         string
	KeyLogPerm         os.FileMode
	PrintKeyLogCreated bool
}

// GenerateTLSConfig builds a bare-bones self-signed TLS config.
// Behavior matches the historical per-example copies when options are set accordingly.
func GenerateTLSConfig(opts TLSConfigOptions) *tls.Config {
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

	cfg := &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: opts.InsecureSkipVerify,
		NextProtos:         opts.NextProtos,
		CipherSuites:       []uint16{tls.TLS_CHACHA20_POLY1305_SHA256},
	}

	if !opts.EnableKeyLog {
		return cfg
	}

	path := opts.KeyLogPath
	if path == "" {
		path = "tls.keylog"
	}
	perm := opts.KeyLogPerm
	if perm == 0 {
		perm = 0600
	}
	keyLogFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		panic(err)
	}
	if opts.PrintKeyLogCreated {
		fmt.Println("TLS keylog file created")
	}
	cfg.KeyLogWriter = keyLogFile
	return cfg
}
