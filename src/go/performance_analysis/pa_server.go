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
	ts_buffer := make([]byte, payload_length)

	for i := 0; i < number_of_analysis_packets; i++ {
		str, err := conn.OpenUniStream() //WithPriority(priority_setting.HighPriority)
		if err != nil {
			panic(err)
		}
		defer str.Close()

		flags := uint8(0)
		binary.LittleEndian.PutUint32(ts_buffer, uint32(flags))
		index := uint32(i)
		binary.LittleEndian.PutUint32(ts_buffer[1:], index)
		// now := time.Now() // TODO: Use BPF instead of here for timestamp
		// binary.LittleEndian.PutUint64(ts_buffer[5:13], uint64(now.UnixNano()))

		// fmt.Println(hex.Dump(ts_buffer))

		n, err := str.Write(ts_buffer)
		if err != nil {
			panic(err)
		}
		if n != len(ts_buffer) {
			panic(fmt.Errorf("wrote %d bytes, expected %d", n, len(ts_buffer)))
		}

		// fmt.Println("Sent timestamp to client")
		time.Sleep(1 * time.Millisecond)
	}

	time.Sleep(1 * time.Second)
	conn.SendDatagram([]byte("END"))
	fmt.Println("Sent END datagram to client")
	time.Sleep(100 * time.Millisecond)
}

func server_datagram_handling(conn quic.Connection) {
	// This one will be replaced by the actual timestamp in the bpf program
	ts_buffer := make([]byte, payload_length)
	for i := 0; i < number_of_analysis_packets; i++ {

		flags := uint8(0)
		binary.LittleEndian.PutUint32(ts_buffer, uint32(flags))
		index := uint32(i)
		binary.LittleEndian.PutUint32(ts_buffer[1:], index)
		now := time.Now() // TODO: Use BPF instead of here for timestamp
		binary.LittleEndian.PutUint64(ts_buffer[5:13], uint64(now.UnixNano()))

		err := conn.SendDatagram(ts_buffer)
		if err != nil {
			panic(err)
		}

		fmt.Println("Sent timestamp to client")
	}
}
