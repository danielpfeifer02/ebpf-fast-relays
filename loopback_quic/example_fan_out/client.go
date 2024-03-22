package main

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/danielpfeifer02/quic-go-prio-packs"
)

type StreamingClient struct {
	stream_list []quic.Stream
}

func NewStreamingClient() *StreamingClient {
	return &StreamingClient{
		stream_list: make([]quic.Stream, 0),
	}
}

func (c *StreamingClient) run() {

	// for now only one stream is supported
	for {
		if len(c.stream_list) > 0 {

			if len(c.stream_list) > 1 {
				fmt.Println("C: For now more than one stream is not supported")
			}

			stream := c.stream_list[0]

			buf := make([]byte, 1024)
			n, err := stream.Read(buf)
			if err != nil {
				return
			}

			fmt.Printf("Client got: %s\n", buf[:n])
		}
	}
}

func (c *StreamingClient) connectToServer() error {

	// dial address
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-streaming-example"},
	}
	fmt.Println("C: Dialing address")
	conn, err := quic.DialAddr(context.Background(), relay_addr, tlsConf, generateQUICConfig())
	if err != nil {
		return err
	}

	fmt.Println("C: Opening stream")
	// Open a new stream with high priority
	stream, err := conn.OpenStreamSyncWithPriority(context.Background(), quic.HighPriority)
	if err != nil {
		return err
	}

	fmt.Println("C: Appending stream")
	c.stream_list = append(c.stream_list, stream)

	return nil
}
