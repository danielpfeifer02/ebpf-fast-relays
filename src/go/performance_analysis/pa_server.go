package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/danielpfeifer02/quic-go-prio-packs"
)

func server() {

	tlsConf := generatePATLSConfig()
	quicConf := generatePAQuicConfig()
	ctx := context.Background()

	listener, err := quic.ListenAddr(server_addr, tlsConf, quicConf)
	if err != nil {
		panic(err)
	}

	conn, err := listener.Accept(ctx)
	if err != nil {
		panic(err)
	}

	if use_datagrams {
		server_datagram_handling(conn)
	} else {
		server_stream_handling(conn, ctx)
	}
}

func server_stream_handling(conn quic.Connection, ctx context.Context) {
	// This one will be replaced by the actual timestamp in the bpf program
	ts_buffer := make([]byte, 8)

	for i := 0; i < 100; i++ {
		str, err := conn.OpenUniStreamSync(ctx) //WithPriority(priority_setting.HighPriority)
		if err != nil {
			panic(err)
		}
		defer str.Close()

		now := time.Now() // TODO: Use BPF instead of here for timestamp
		binary.LittleEndian.PutUint64(ts_buffer, uint64(now.UnixNano()))

		n, err := str.Write(ts_buffer)
		if err != nil {
			panic(err)
		}
		if n != len(ts_buffer) {
			panic(fmt.Errorf("wrote %d bytes, expected %d", n, len(ts_buffer)))
		}

		// fmt.Println("Sent timestamp to client")
	}

	time.Sleep(100 * time.Millisecond)
	conn.SendDatagram([]byte("END"))
	fmt.Println("Sent END datagram to client")
	time.Sleep(100 * time.Millisecond)
}

func server_datagram_handling(conn quic.Connection) {
	// This one will be replaced by the actual timestamp in the bpf program
	ts_buffer := make([]byte, 8)
	for i := 0; i < 50; i++ {
		err := conn.SendDatagram(ts_buffer)
		if err != nil {
			panic(err)
		}

		fmt.Println("Sent timestamp to client -", 8, "bytes")
	}
}
