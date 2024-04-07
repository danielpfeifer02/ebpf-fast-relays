package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"runtime"

	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/danielpfeifer02/quic-go-prio-packs/priority_setting"
)

type StreamingClient struct {
	stream_list []quic.Stream
}

func NewStreamingClient() *StreamingClient {
	return &StreamingClient{
		stream_list: make([]quic.Stream, 0),
	}
}

// TODO structure better
func (c *StreamingClient) run() {

	fmt.Println("Number of goroutines:", runtime.NumGoroutine())

	// for now only one stream is supported
	for {
		if len(c.stream_list) > 0 {

			if len(c.stream_list) > 1 {
				fmt.Println("C: For now more than one stream is not supported")
			}

			stream := c.stream_list[0]

			buf := make([]byte, 1)
			// fmt.Println("C: Reading from stream")
			n, err := stream.Read(buf)
			if err != nil {
				panic(err)
			}

			// fmt.Printf("Client got: %s\n", buf[:n])
			fmt.Printf("%s", buf[:n])
		}
	}
}

func (c *StreamingClient) connectToServer() error {

	// dial address
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-streaming-example"},
	}
	fmt.Println("C: Dialing address", relay_addr)
	// client_addr := net.IPv4(192, 168, 1, 4)
	// conn, err := quic.DialAddrExt(context.Background(), relay_addr, "veth3", tlsConf, generateQUICConfig())
	conn, err := quic.DialAddr(context.Background(), relay_addr, tlsConf, generateQUICConfig())
	if err != nil {
		fmt.Printf("C: Error dialing address (%v)\n", err)
		return err
	}

	fmt.Println("C: Opening stream")
	// Open a new stream with high priority
	stream, err := conn.OpenStreamSyncWithPriority(context.Background(), priority_setting.HighPriority)
	if err != nil {
		return err
	}

	fmt.Println("C: Appending stream")
	c.stream_list = append(c.stream_list, stream)

	return nil
}
