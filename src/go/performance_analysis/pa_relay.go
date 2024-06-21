package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/danielpfeifer02/quic-go-prio-packs"
)

func relay() {

	tlsConf := generatePATLSConfig()
	quicConf := generatePAQuicConfig()
	ctx := context.Background()

	listener, err := quic.ListenAddr(relay_addr, tlsConf, quicConf)
	if err != nil {
		panic(err)
	}

	client_conn, err := listener.Accept(ctx)
	if err != nil {
		panic(err)
	}

	server_conn, err := quic.DialAddr(ctx, server_addr, tlsConf, quicConf)
	if err != nil {
		panic(err)
	}

	if use_datagrams {
		// TODO: datagram setup doesn't make sense with end notification also being a datagram
		relay_datagram_handling(server_conn, client_conn, ctx)
	} else {
		end_chan := make(chan struct{})
		go func() {
			dtg, err := server_conn.ReceiveDatagram(ctx)
			if err != nil {
				fmt.Println("Error receiving datagram from server")
				panic(err)
			}
			fmt.Println("Received END datagram from server")
			client_conn.SendDatagram(dtg)
			time.Sleep(100 * time.Millisecond)
			os.Exit(0)
			time.Sleep(100 * time.Millisecond)
			end_chan <- struct{}{}
		}()
		relay_stream_handling(server_conn, client_conn, ctx, end_chan)
	}
}

func relay_stream_handling(server_conn, client_conn quic.Connection, ctx context.Context, end_chan chan struct{}) {
	ts_buffer := make([]byte, 8)

	for {
		select {
		case <-end_chan:
			return // TODO: not working
		default:
			// Recieve from server
			server_str, err := server_conn.AcceptUniStream(ctx)
			if err != nil {
				fmt.Println("Error accepting stream from server")
				panic(err)
			}

			n, err := server_str.Read(ts_buffer)
			if err != nil {
				fmt.Println("Error reading from server")
				panic(err)
			}

			// Send to client
			client_str, err := client_conn.OpenUniStreamSync(ctx) //WithPriority(priority_setting.HighPriority)
			if err != nil {
				fmt.Println("Error opening stream to client")
				panic(err)
			}
			// defer client_str.Close()

			_, err = client_str.Write(ts_buffer[:n])
			if err != nil {
				fmt.Println("Error writing to client")
				panic(err)
			}
		}
	}
}

func relay_datagram_handling(server_conn, client_conn quic.Connection, ctx context.Context) {
	for {

		// Recieve from server
		ts_buffer, err := server_conn.ReceiveDatagram(ctx)
		if err != nil {
			fmt.Println("Error receiving datagram from server")
			panic(err)
		}
		if string(ts_buffer) == "END" {
			return
		}

		// Send to client
		err = client_conn.SendDatagram(ts_buffer)
		if err != nil {
			fmt.Println("Error sending datagram to client")
			panic(err)
		}

	}
}
