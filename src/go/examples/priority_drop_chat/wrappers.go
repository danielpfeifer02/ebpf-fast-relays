package main

import (
	"context"

	"github.com/danielpfeifer02/quic-go-prio-packs"
)

func connectionAcceptWrapper(listener *quic.Listener, channel chan quic.Connection) {
	for {
		debugPrint("before")
		conn, err := listener.Accept(context.Background())
		debugPrint("after")
		if err != nil {
			panic(err)
		}
		channel <- conn
	}
}

func streamAcceptWrapperRelay(connection quic.Connection, s *RelayServer) {
	ctx := context.TODO()
	for {
		stream, err := connection.AcceptStream(ctx)
		if err != nil {
			panic(err)
		}
		s.connection_lookup[stream] = connection
		s.stream_chan <- stream
	}
}

func streamAcceptWrapperServer(connection quic.Connection, channel chan quic.Stream) {
	ctx := context.TODO()
	for {
		stream, err := connection.AcceptStream(ctx)
		if err != nil {
			panic(err)
		}
		channel <- stream
	}
}
