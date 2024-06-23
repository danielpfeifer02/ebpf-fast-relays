package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/danielpfeifer02/quic-go-prio-packs"
)

type sent_recv struct {
	sent_ts uint64
	recv_ts uint64
}

var (
	times map[uint32][]sent_recv
)

var lock = &sync.Mutex{}

func client() {

	tlsConf := generatePATLSConfig()
	quicConf := generatePAQuicConfig()
	ctx := context.Background()

	conn, err := quic.DialAddr(ctx, relay_addr, tlsConf, quicConf)
	if err != nil {
		panic(err)
	}

	times = make(map[uint32][]sent_recv)
	ctr := 0

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

			for i, sent_recv_list := range times {
				if len(sent_recv_list) != 2 {
					if count_errors {
						fmt.Println("expected 2 timestamps, got", len(sent_recv_list), "for index", i, "-", ctr, "th time this is happening")
						ctr++
						continue
					}
					// TODO: why does this happen? Why are some packets lost even with loss 0%?
					panic(fmt.Errorf("expected 2 timestamps, got %d for index %d", len(sent_recv_list), i))
				}
				sent_ts_1 := sent_recv_list[0].sent_ts
				recv_ts_1 := sent_recv_list[0].recv_ts
				latency_1 := recv_ts_1 - sent_ts_1

				sent_ts_2 := sent_recv_list[1].sent_ts
				recv_ts_2 := sent_recv_list[1].recv_ts
				latency_2 := recv_ts_2 - sent_ts_2

				fmt.Println("Latency 1:", time.Unix(0, int64(latency_1)).Sub(time.Unix(0, 0)))
				fmt.Println("Latency 2:", time.Unix(0, int64(latency_2)).Sub(time.Unix(0, 0)))
				fmt.Println("Latency Difference:", time.Unix(0, int64(latency_2)).Sub(time.Unix(0, int64(latency_1))))
				fmt.Println()

			}

			time.Sleep(1 * time.Second)
			os.Exit(0)
			end_chan <- struct{}{}
		}(end_chan)
		client_stream_handling(conn, ctx, end_chan)
	}
}

func client_stream_handling(relay_conn quic.Connection, ctx context.Context, end_chan chan struct{}) {
	ts_buffer := make([]byte, 12)

	for {
		select {
		case <-end_chan:
			return // TODO: not working
		default:
			fmt.Println("Waiting for Stream...")
			str, err := relay_conn.AcceptUniStream(ctx)
			if err != nil {
				panic(err)
			}

			fmt.Printf("Waiting for Timestamp on stream with id %d...\n", str.StreamID())
			n, err := str.Read(ts_buffer)
			if err != nil {
				panic(err)
			}

			if n != 12 {
				panic(fmt.Errorf("got %d bytes, expected %d", n, 12))
			}

			now := time.Now().UnixNano()

			data := ts_buffer[:n]
			sent_index := binary.LittleEndian.Uint32(data[0:4])
			sent_ts := binary.LittleEndian.Uint64(data[4:12])

			fmt.Println("Received Timestamp for index", sent_index, "from server")

			lock.Lock()
			if _, ok := times[sent_index]; !ok {
				times[sent_index] = make([]sent_recv, 0)
			}
			srv := sent_recv{sent_ts, uint64(now)}
			times[sent_index] = append(times[sent_index], srv)
			lock.Unlock()

			// latency := now - int64(sent_ts)
			// fmt.Println("Latency:", latency)
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
