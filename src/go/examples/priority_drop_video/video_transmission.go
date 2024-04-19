package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"math/big"
	"os"

	"github.com/mengelbart/gst-go"
)

const video_server_address = "192.168.10.1:4242"
const relay_server_address = "192.168.11.2:4242"

func video_main(user string) {

	gst.GstInit()
	defer gst.GstDeinit()

	if user == "server" {
		if err := server(); err != nil {
			log.Fatal(err)
		}
		return
	} else if user == "relay" {
		if err := relay(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := client(); err != nil {
		log.Fatal(err)
	}
}

// Setup a bare-bones TLS config for the server
func video_generateTLSConfig() *tls.Config {
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
	keylogFile, err := os.Create("keylog.txt")
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: true,
		NextProtos:         []string{"moq-00"},
		KeyLogWriter:       keylogFile,
	}
}

/* Maybe explore if direclty handling quic streams is more efficient

func video_generateQuicConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams: true,
	}
}

func passOnVideo(server_conn quic.Connection, server_str quic.Stream, client_list []Client) {

	// Pass on datagrams from the server to all clients
	go func(s_c quic.Connection, c_lst []Client) {
		for {
			buf, err := s_c.ReceiveDatagram(context.Background())
			if err != nil {
				panic(err)
			}
			for _, c := range c_lst {
				err := c.conn.SendDatagram(buf)
				if err != nil {
					panic(err)
				}
			}
		}
	}(server_conn, client_list)

	// Pass on stream data from the server to all clients
	go func(s_str quic.Stream, c_lst []Client) {
		for {
			buf := make([]byte, 64_000)
			n, err := s_str.Read(buf)
			if err != nil {
				panic(err)
			}
			for _, c := range c_lst {
				_, err := c.stream.Write(buf[:n])
				if err != nil {
					panic(err)
				}
			}

		}
	}(server_str, client_list)
}

func relay_plain_quic() error {

	fmt.Println("connecting to server")

	server_conn, err := quic.DialAddr(context.Background(),
		video_server_address, video_generateTLSConfig(), video_generateQuicConfig())
	if err != nil {
		panic(err)
	}
	fmt.Println("connected to server")
	server_str, err := server_conn.OpenStreamSync(context.Background())
	if err != nil {
		panic(err)
	}
	fmt.Println("opened stream to server")

	client_listener, err := quic.ListenAddr(relay_server_address,
		video_generateTLSConfig(), video_generateQuicConfig())
	if err != nil {
		panic(err)
	}
	fmt.Println("listening for clients")

	client_list := make([]Client, 0)

	go passOnVideo(server_conn, server_str, client_list)

	for {
		c_conn, err := client_listener.Accept(context.Background())
		if err != nil {
			panic(err)
		}
		fmt.Println("accepted client connection")

		go func(c_conn quic.Connection) {

			c_str, err := c_conn.AcceptStream(context.Background())
			if err != nil {
				panic(err)
			}
			fmt.Println("accepted client stream")
			client := Client{
				conn:   c_conn,
				stream: c_str,
			}
			client_list = append(client_list, client)

			go func(c_str quic.Stream) {
				for {
					buf := make([]byte, 64_000)
					n, err := c_str.Read(buf)
					if err != nil {
						panic(err)
					}
					// send to server
					fmt.Println("sending to server")
					_, err = server_str.Write(buf[:n])
					if err != nil {
						panic(err)
					}
				}
			}(c_str)
		}(c_conn)

		fmt.Println("new client connected")
	}

}
*/
