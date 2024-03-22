package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/danielpfeifer02/quic-go-prio-packs"
)

const server_addr = "192.168.1.1:4242"
const relay_addr = "192.168.1.3:4242"

type StreamingStream struct {
	stream     quic.Stream
	connection quic.Connection
}

type Server interface {
	run() error
}

type StreamingServer struct {
	conn_chan      chan quic.Connection
	stream_chan    chan quic.Stream
	interrupt_chan chan bool
	stream_list    []quic.Stream
}

var _ Server = &StreamingServer{}

func NewStreamingServer() *StreamingServer {
	return &StreamingServer{
		conn_chan:      make(chan quic.Connection),
		stream_chan:    make(chan quic.Stream),
		interrupt_chan: make(chan bool),
		stream_list:    make([]quic.Stream, 0),
	}
}

func (s *StreamingServer) run() error {
	// delete tls.keylog file if present
	// os.Remove("tls.keylog")
	listener, err := quic.ListenAddr(server_addr, generateTLSConfig(), generateQUICConfig())
	if err != nil {
		return err
	}

	done := make(chan struct{})

	// separate goroutine that handles all connections, interrupts and message sendings
	go func() {

		go connectionAcceptWrapper(listener, s.conn_chan)

		for {

			select {

			case <-s.interrupt_chan:
				fmt.Println("S: Terminate server")
				// close all streams
				for _, stream := range s.stream_list {
					stream.Close()
				}
				listener.Close()
				done <- struct{}{}
				return

			case stream := <-s.stream_chan:
				s.stream_list = append(s.stream_list, stream)
				fmt.Println("S: New stream added")

			case conn := <-s.conn_chan:
				fmt.Println("S: New connection accepted")
				go streamAcceptWrapperServer(conn, s.stream_chan)
			}

			// TODO add something to unsubscribe from the server (i.e. remove stream)

		}

	}()

	<-done
	fmt.Println("Server done")

	return nil
}

func (s *StreamingServer) sendToAll(message string) {
	for _, stream := range s.stream_list {
		_, err := stream.Write([]byte(message))
		if err != nil {
			panic(err)
		}
	}
}

type RelayServer struct {
	conn_chan               chan quic.Connection
	stream_chan             chan quic.Stream
	interrupt_chan          chan bool
	stream_list             []quic.Stream
	stream_pairs            map[quic.Stream]quic.Stream
	connection_pairs        map[quic.Connection]quic.Connection
	stream_connection_pairs map[quic.Stream]quic.Connection
}

var _ Server = &RelayServer{}

func NewRelayServer() *RelayServer {
	return &RelayServer{
		conn_chan:      make(chan quic.Connection),
		stream_chan:    make(chan quic.Stream),
		interrupt_chan: make(chan bool),
		stream_list:    make([]quic.Stream, 0),
	}
}

func (s *RelayServer) run() error {
	listener, err := quic.ListenAddr(relay_addr, generateTLSConfig(), generateQUICConfig())
	if err != nil {
		return err
	}

	done := make(chan struct{})

	// separate goroutine that handles all connections, interrupts and message sendings
	go func() {

		// TODO how to terminate correctly?
		go connectionAcceptWrapper(listener, s.conn_chan)

		for {

			select {

			case <-s.interrupt_chan:
				fmt.Println("R: Terminate relay")
				// close all streams
				for _, stream := range s.stream_list {
					stream.Close()
				}
				listener.Close()
				done <- struct{}{}
				return

			// TODO create new stream to the server
			case stream := <-s.stream_chan:
				s.stream_list = append(s.stream_list, stream)

				client_connection := s.stream_connection_pairs[stream]

				// Open a new stream with high priority to server
				server_connection := s.connection_pairs[client_connection]
				server_stream, err := server_connection.OpenStreamSyncWithPriority(context.Background(), quic.HighPriority)
				if err != nil {
					panic(err)
				}

				s.stream_pairs[stream] = server_stream
				s.stream_pairs[server_stream] = stream

				// set listening routine for the new stream correctly

				fmt.Println("R: New stream added")

			// TODO create new stream to the server
			case conn := <-s.conn_chan:
				fmt.Println("R: New connection accepted")

				tlsConf := &tls.Config{
					InsecureSkipVerify: true,
					NextProtos:         []string{"quic-streaming-example"},
				}
				fmt.Println("R: Dialing server address")
				conn_to_server, err := quic.DialAddr(context.Background(), server_addr, tlsConf, generateQUICConfig())
				if err != nil {
					panic(err)
				}

				s.connection_pairs[conn] = conn_to_server
				s.connection_pairs[conn_to_server] = conn

				go streamAcceptWrapperRelay(conn, s)
			}

			// TODO add something to unsubscribe from the server (i.e. remove stream)

		}

	}()

	<-done
	fmt.Println("Relay done")

	return nil
}

func (s *RelayServer) connectToServer(clientConnection quic.Connection) error {
	// dial address

	// fmt.Println("R: Opening stream")
	// // Open a new stream with high priority
	// stream, err := conn.OpenStreamSyncWithPriority(context.Background(), quic.HighPriority)
	// if err != nil {
	// 	return err
	// }

	// fmt.Println("R: Appending stream")
	// s.stream_list = append(s.stream_list, stream)

	return nil
}

func connectionAcceptWrapper(listener *quic.Listener, channel chan quic.Connection) {
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			panic(err)
		}
		channel <- conn
	}
}

func streamAcceptWrapperRelay(connection quic.Connection, s *RelayServer) {
	for {
		stream, err := connection.AcceptStream(context.Background())
		if err != nil {
			panic(err)
		}
		s.stream_connection_pairs[stream] = connection
		s.stream_chan <- stream
	}
}

func streamAcceptWrapperServer(connection quic.Connection, channel chan quic.Stream) {
	for {
		stream, err := connection.AcceptStream(context.Background())
		if err != nil {
			panic(err)
		}
		channel <- stream
	}
}

// Setup a bare-bones TLS config for the server
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

	// Create a KeyLogWriter
	// keyLogFile, err := os.OpenFile("tls.keylog", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	// if err != nil {
	// 	panic(err)
	// }
	// defer keyLogFile.Close() // TODO why not close?

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-streaming-example"},
		// KeyLogWriter: keyLogFile,
		CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256},
	}
}

func generateQUICConfig() *quic.Config {
	return &quic.Config{}
}
