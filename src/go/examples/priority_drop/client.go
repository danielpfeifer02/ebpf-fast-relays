package main

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/danielpfeifer02/quic-go-prio-packs/priority_setting"
)

type StreamingClient struct {
	stream_list []quic.Stream
	relay_conn  quic.Connection
}

func NewStreamingClient() *StreamingClient {
	return &StreamingClient{
		stream_list: make([]quic.Stream, 0),
		relay_conn:  nil,
	}
}

// TODO structure better
func (c *StreamingClient) run() {

	// fmt.Println("Number of goroutines:", runtime.NumGoroutine())

	for _, stream := range c.stream_list {
		go c.handleStream(stream)
	}

	for {

		data, err := c.relay_conn.ReceiveDatagram(context.Background())
		if err != nil {
			fmt.Printf("C: Error receiving datagram (%v)\n", err)
			return
		}
		fmt.Printf("C: Received datagram: %s\n", data)

	}
}

func (c *StreamingClient) handleStream(stream quic.Stream) {
	for {
		data := make([]byte, 1024)
		n, err := stream.Read(data)
		if err != nil {
			fmt.Printf("C: Error reading stream (%v)\n", err)
			return
		}
		fmt.Printf("C: Received message: %s\n", data[:n])
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
	c.relay_conn = conn

	fmt.Println("C: Opening stream")
	// Open a new stream with no priority
	high_stream, err := conn.OpenStreamSyncWithPriority(context.Background(), priority_setting.NoPriority)
	if err != nil {
		return err
	}
	fmt.Println("C: Appending stream")
	c.stream_list = append(c.stream_list, high_stream)

	// fmt.Println("C: Opening low prio stream")
	// // Open a new stream with low priority
	// low_stream, err := conn.OpenStreamSyncWithPriority(context.Background(), priority_setting.LowPriority)
	// if err != nil {
	// 	return err
	// }
	// fmt.Println("C: Appending low prio stream")
	// c.stream_list = append(c.stream_list, low_stream)

	// fmt.Println("C: Opening high prio stream")
	// // Open a new stream with high priority
	// high_stream, err := conn.OpenStreamSyncWithPriority(context.Background(), priority_setting.HighPriority)
	// if err != nil {
	// 	return err
	// }
	// fmt.Println("C: Appending high prio stream")
	// c.stream_list = append(c.stream_list, high_stream)

	return nil
}
