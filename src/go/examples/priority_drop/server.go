package main

import (
	"fmt"
	"time"

	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/danielpfeifer02/quic-go-prio-packs/priority_setting"
)

const server_addr = "192.168.10.1:4242"
const relay_addr = "192.168.11.2:4242"

const DEBUG_PRINT = false

var bpf_enabled = true

type Server interface {
	run() error
}

type StreamingServer struct {
	conn_chan         chan quic.Connection
	stream_chan       chan quic.Stream
	interrupt_chan    chan bool
	stream_list       []quic.Stream
	high_prio_streams []quic.Stream
	low_prio_streams  []quic.Stream
	relay_conn        quic.Connection
}

var _ Server = &StreamingServer{}

func NewStreamingServer() *StreamingServer {
	return &StreamingServer{
		conn_chan:      make(chan quic.Connection),
		stream_chan:    make(chan quic.Stream),
		interrupt_chan: make(chan bool),
		stream_list:    make([]quic.Stream, 0),
		// TODO set high_prio_stream and low_prio_stream
		high_prio_streams: make([]quic.Stream, 0),
		low_prio_streams:  make([]quic.Stream, 0),
		relay_conn:        nil,
	}
}

func (s *StreamingServer) run() error {

	// fmt.Println("Number of goroutines:", runtime.NumGoroutine())

	// delete tls.keylog file if present
	// os.Remove("tls.keylog")
	listener, err := quic.ListenAddr(server_addr, generateTLSConfig(true), generateQUICConfig())
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

				stream_prio := stream.Priority()
				if stream_prio == priority_setting.HighPriority {
					fmt.Println("S: Added high prio stream")
					s.high_prio_streams = append(s.high_prio_streams, stream)
				} else if stream_prio == priority_setting.LowPriority {
					fmt.Println("S: Added low prio stream")
					s.low_prio_streams = append(s.low_prio_streams, stream)
				} else {
					fmt.Println("S: Added stream with unknown priority")
				}

			case conn := <-s.conn_chan:
				fmt.Println("S: New connection accepted")
				if s.relay_conn == nil {
					s.relay_conn = conn
				}
				go streamAcceptWrapperServer(conn, s.stream_chan)
			}

			// TODO add something to unsubscribe from the server (i.e. remove stream)

		}

	}()

	<-done
	fmt.Println("Server done")

	return nil
}

func sendToStream(stream *quic.Stream, message string) {
	for i := 0; i < 1; i++ {
		_, err := (*stream).Write([]byte(message))
		if err != nil {
			panic(err)
		}
		time.Sleep(10.0 * time.Millisecond)
	}
}

func (s *StreamingServer) sendToAll(message string, prio priority_setting.Priority, datagram bool) {

	if datagram {
		fmt.Println("S: sending datagram with priority", prio)
		s.relay_conn.SendDatagramWithPriority([]byte(message), prio)
	} else if prio == priority_setting.HighPriority {
		fmt.Println("S: sending message with high priority")
		for _, stream := range s.high_prio_streams {
			sendToStream(&stream, message)
		}
	} else if prio == priority_setting.LowPriority {
		fmt.Println("S: sending message with low priority")
		for _, stream := range s.low_prio_streams {
			sendToStream(&stream, message)
		}
	} else {
		fmt.Println("Unknown priority")
	}
}
