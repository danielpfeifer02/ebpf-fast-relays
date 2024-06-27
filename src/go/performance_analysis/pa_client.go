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
	sent_ts           uint64
	recv_ts           uint64
	through_userspace bool
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

	// Open output/results.txt file
	f, err := os.Create("output/results.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

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
				l1_type := "Userspace"
				if !sent_recv_list[0].through_userspace {
					l1_type = "Kernel"
				}

				sent_ts_2 := sent_recv_list[1].sent_ts
				recv_ts_2 := sent_recv_list[1].recv_ts
				latency_2 := recv_ts_2 - sent_ts_2
				l2_type := "Userspace"
				if !sent_recv_list[1].through_userspace {
					l2_type = "Kernel"
				}

				fmt.Println(l1_type, "Latency 1:", time.Unix(0, int64(latency_1)).Sub(time.Unix(0, 0)))
				fmt.Println(l2_type, "Latency 2:", time.Unix(0, int64(latency_2)).Sub(time.Unix(0, 0)))
				fmt.Println("Latency Difference:", time.Unix(0, int64(latency_2)).Sub(time.Unix(0, int64(latency_1))))
				fmt.Println("Raw Nanosecond Difference:", latency_2-latency_1)
				fmt.Println()

				_, err := f.WriteString(fmt.Sprintf("%d %d %d %s %d %d %s %d\n", i, sent_ts_1, recv_ts_1, l1_type, sent_ts_2, recv_ts_2, l2_type, latency_2-latency_1))
				if err != nil {
					panic(err)
				}

			}

			time.Sleep(1 * time.Second)
			os.Exit(0)
			end_chan <- struct{}{}
		}(end_chan)
		client_stream_handling(conn, ctx, end_chan)
	}
}

func client_stream_handling(relay_conn quic.Connection, ctx context.Context, end_chan chan struct{}) {
	ts_buffer := make([]byte, payload_length)

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

			// TODO: if packet is split this panic seems to happen
			if n != len(ts_buffer) {
				panic(fmt.Errorf("got %d bytes, expected %d", n, len(ts_buffer)))
			}

			// now := time.Now().UnixNano()

			data := ts_buffer[:n]
			flag := data[0]
			sent_index := binary.LittleEndian.Uint32(data[1:5])
			sent_ts := binary.LittleEndian.Uint64(data[5:13])
			recv_ts := binary.LittleEndian.Uint64(data[13:21])

			fmt.Printf("Received Timestamp for index %d from server (%x)\n", sent_index, flag)

			lock.Lock()
			if _, ok := times[sent_index]; !ok {
				times[sent_index] = make([]sent_recv, 0)
			}
			through_userspace := flag&USERSPACE_FLAG != 0
			// srv := sent_recv{sent_ts, uint64(now), through_userspace}
			srv := sent_recv{sent_ts, recv_ts, through_userspace}
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

		_ = datagram[0]
		_ = binary.LittleEndian.Uint32(datagram[1:5])
		sent_ts := binary.LittleEndian.Uint64(datagram[5:13])
		now := time.Now().UnixNano()
		latency := now - int64(sent_ts)
		fmt.Println("Latency:", latency)

	}
}
