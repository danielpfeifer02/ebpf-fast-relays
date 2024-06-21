package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/danielpfeifer02/quic-go-prio-packs"
)

func client() {

	tlsConf := generatePATLSConfig()
	quicConf := generatePAQuicConfig()
	ctx := context.Background()

	conn, err := quic.DialAddr(ctx, relay_addr, tlsConf, quicConf)
	if err != nil {
		panic(err)
	}

	if use_datagrams {
		client_datagram_handling(conn, ctx)
	} else {
		end_chan := make(chan struct{})
		go func(end_chan chan struct{}) {
			_, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				fmt.Println("Error receiving datagram from server")
				panic(err)
			}
			fmt.Println("Received END datagram from server")
			os.Exit(0)
			end_chan <- struct{}{}
		}(end_chan)
		client_stream_handling(conn, ctx, end_chan)
	}
}

func client_stream_handling(relay_conn quic.Connection, ctx context.Context, end_chan chan struct{}) {
	ts_buffer := make([]byte, 8)

	for {
		select {
		case <-end_chan:
			return // TODO: not working
		default:
			str, err := relay_conn.AcceptUniStream(ctx)
			if err != nil {
				panic(err)
			}

			n, err := str.Read(ts_buffer)
			if err != nil {
				panic(err)
			}

			sent_ts := binary.LittleEndian.Uint64(ts_buffer[:n])
			now := time.Now().UnixNano()
			latency := now - int64(sent_ts)
			fmt.Println("Latency:", latency)
		}
	}
}

func client_datagram_handling(relay_conn quic.Connection, ctx context.Context) {
	for {

		datagram, err := relay_conn.ReceiveDatagram(ctx)
		if err != nil {
			panic(err)
		}
		if string(datagram) == "END" {
			return
		}

		sent_ts := binary.LittleEndian.Uint64(datagram)
		now := time.Now().UnixNano()
		latency := now - int64(sent_ts)
		fmt.Println("Latency:", latency)

	}
}
