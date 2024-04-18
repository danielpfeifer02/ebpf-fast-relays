package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	moqtransport "github.com/danielpfeifer02/priority-moqtransport"
	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/mengelbart/gst-go"
)

const video_server_address = "192.168.10.1:1909"
const relay_server_address = "192.168.11.2:1909"

type Client struct {
	conn   quic.Connection
	stream quic.Stream
}

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

func server() error {
	s := moqtransport.Server{
		Handler: moqtransport.PeerHandlerFunc(func(p *moqtransport.Peer) {
			log.Println("handling new peer")
			defer log.Println("XXX")
			p.OnAnnouncement(func(s string) error {
				log.Printf("got announcement: %v", s)
				return nil
			})
			if err := p.Announce("video"); err != nil {
				log.Printf("failed to announce video: %v", err)
			}
			log.Println("announced video namespace")
			p.OnSubscription(func(s string, st *moqtransport.SendTrack) (uint64, time.Duration, error) {
				log.Printf("handling subscription to track %s", s)
				if s != "video" {
					return 0, 0, errors.New("unknown trackname")
				}
				p, err := gst.NewPipeline("videotestsrc ! queue ! videoconvert ! jpegenc ! multipartmux ! appsink name=appsink")
				if err != nil {
					log.Fatal(err)
				}
				p.SetBufferHandler(func(b gst.Buffer) {
					if _, err := st.Write(b.Bytes); err != nil {
						panic(err)
					}
				})
				p.SetEOSHandler(func() {
					p.Stop()
				})
				p.SetErrorHandler(func(err error) {
					log.Println(err)
					p.Stop()
				})
				p.Start()
				return 0, 0, nil
			})
		}),
		TLSConfig: video_generateTLSConfig(),
	}
	if err := s.ListenQUIC(context.Background(), video_server_address); err != nil {
		panic(err)
	}
	return nil
}

func relay() error {

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

func client() error {
	announcementCh := make(chan string)
	closeCh := make(chan struct{})

	c, err := moqtransport.DialQUIC(context.Background(), relay_server_address)
	if err != nil {
		panic(err)
	}

	log.Println("moq peer connected")
	c.OnAnnouncement(func(s string) error {
		log.Printf("handling announcement of track %v", s)
		announcementCh <- s
		return nil
	})

	trackname := <-announcementCh
	log.Printf("got announcement: %v", trackname)
	p, err := gst.NewPipeline("appsrc name=src ! multipartdemux ! jpegdec ! autovideosink")
	if err != nil {
		panic(err)
	}
	t, err := c.Subscribe(trackname)
	if err != nil {
		panic(err)
	}
	p.SetEOSHandler(func() {
		p.Stop()
		closeCh <- struct{}{}
	})
	p.SetErrorHandler(func(err error) {
		log.Println(err)
		p.Stop()
		closeCh <- struct{}{}
	})
	p.Start()
	log.Println("starting pipeline")
	go func() {
		for {
			log.Println("reading from track")
			buf := make([]byte, 64_000)
			n, err := t.Read(buf)
			if err != nil {
				log.Printf("error on read: %v", err)
				p.SendEOS()
			}
			log.Printf("writing %v bytes from stream to pipeline", n)
			_, err = p.Write(buf[:n])
			if err != nil {
				log.Printf("error on write: %v", err)
				p.SendEOS()
			}
		}
	}()

	ml := gst.NewMainLoop()
	go func() {
		<-closeCh
		ml.Stop()
	}()
	ml.Run()
	return nil
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

func video_generateQuicConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams: true,
	}
}
