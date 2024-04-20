package main

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/danielpfeifer02/quic-go-prio-packs/priority_setting"
)

type RelayServer struct {
	conn_chan               chan quic.Connection
	stream_chan             chan quic.Stream
	interrupt_chan          chan bool
	connection_list         []quic.Connection
	client_list             []client_connection
	connection_lookup       map[quic.Stream]quic.Connection
	server_connection       quic.Connection
	server_stream_high_prio quic.Stream
	server_stream_low_prio  quic.Stream
}

var _ Server = &RelayServer{}

// TODO check which maps are actually needed
func NewRelayServer() *RelayServer {
	return &RelayServer{
		conn_chan:               make(chan quic.Connection),
		stream_chan:             make(chan quic.Stream),
		interrupt_chan:          make(chan bool),
		connection_list:         make([]quic.Connection, 0),
		client_list:             make([]client_connection, 0),
		connection_lookup:       make(map[quic.Stream]quic.Connection),
		server_connection:       nil,
		server_stream_high_prio: nil,
		server_stream_low_prio:  nil,
	}
}

func (s *RelayServer) run() error {

	// fmt.Println("Number of goroutines:", runtime.NumGoroutine())

	listener, err := quic.ListenAddr(relay_addr, generateTLSConfig(true), generateQUICConfig())
	if err != nil {
		fmt.Printf("\nError: %v\n", err)
		return err
	}
	fmt.Println("R: Relay up")

	done := make(chan struct{})

	// Just for the compiler to not complain
	var number_of_clients *ebpf.Map
	// TODO: needed?
	// var client_pn *ebpf.Map
	var client_ctr uint32
	if bpf_enabled {
		clearBPFMaps()

		number_of_clients, err = ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/number_of_clients", &ebpf.LoadPinOptions{})
		if err != nil {
			panic(err)
		}
		client_ctr := uint32(0)
		// set number of clients to 0
		err = number_of_clients.Update(uint32(0), client_ctr, 0)
		debugPrint("Update at point nr.", 1)
		if err != nil {
			panic(err)
		}

		id_counter, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/id_counter", &ebpf.LoadPinOptions{})
		if err != nil {
			panic(err)
		}
		err = id_counter.Update(uint32(0), uint32(0), 0)
		debugPrint("Update at point nr.", 2)
		if err != nil {
			panic(err)
		}

		// connection_map, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/connection_established", &ebpf.LoadPinOptions{})
		// if err != nil {
		// 	panic(err)
		// }

		// err = connection_map.Update(uint32(0), uint8(0), 0)
		// if err != nil {
		// 	panic(err)
		// }

		// TODO: needed?
		// client_pn, err = ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/client_pn", &ebpf.LoadPinOptions{})
		// if err != nil {
		// 	panic(err)
		// }
	}

	// separate goroutine that handles all connections, interrupts and message sendings
	go func() {

		// TODO how to terminate correctly?
		go connectionAcceptWrapper(listener, s.conn_chan)

		for {

			select {

			case <-s.interrupt_chan: // TODO: add graceful shutdown
				fmt.Println("R: Terminate relay")
				// close all streams
				for _, client_conn := range s.client_list {
					client_conn.stream.Close()
				}
				listener.Close()
				done <- struct{}{}
				return

			case stream := <-s.stream_chan:
				conn := s.connection_lookup[stream]
				client := client_connection{
					conn:   conn,
					stream: stream,
				}
				s.client_list = append(s.client_list, client)

				// if s.server_stream == nil {
				// 	if s.server_connection == nil {
				// 		panic("Server connection not initialized")
				// 	}
				// 	server_stream, err := s.server_connection.OpenStreamSyncWithPriority(context.Background(), priority_setting.HighPriority)
				// 	if err != nil {
				// 		panic(err)
				// 	}
				// 	s.server_stream = server_stream
				// 	go passOnTraffic(s)

				// 	go publishConnectionEstablished(conn)
				// }

				fmt.Println("R: New stream added")

			case conn := <-s.conn_chan:

				// TODO: why ip address of bridge instead of client?
				ipaddr, port := getIPAndPort(conn)
				fmt.Printf("R: New connection accepted (from %s at port %d)\n", ipaddr.String(), port)

				if bpf_enabled {

					client_ctr++
					err = number_of_clients.Update(uint32(0), client_ctr, 0)
					debugPrint("Update at point nr.", 8)
					if err != nil {
						panic(err)
					}
					fmt.Printf("R: Number of clients is now: %d\n", client_ctr)

					// TODO: needed?
					// resetting client_pn
					// the first pn has to be set to 1 since 0 is already implicitly used by the library (TODO: verify)
					// since the map holds the *next usable pn* it needs to hold 1 in the beginning
					// one_pn := pn_struct{
					// 	Pn:      uint16(1),
					// 	Changed: uint8(1),
					// 	Padding: [3]uint8{0, 0, 0},
					// }
					// key := client_key_struct{
					// 	Ipaddr:  swapEndianness32(ipToInt32(ipaddr)),
					// 	Port:    swapEndianness16(uint16(port)),
					// 	Padding: [2]uint8{0, 0},
					// }
					// err = client_pn.Update(key, one_pn, 0)
					// if err != nil {
					// 	fmt.Println("Error updating client_pn")
					// 	panic(err)
					// }

					fmt.Println("R: Client packet number map reset")

					go packetNumberHandler(conn)

				}

				if s.server_connection == nil {
					tlsConf := &tls.Config{
						InsecureSkipVerify: true,
						NextProtos:         []string{"quic-streaming-example"},
					}
					fmt.Println("R: Dialing server address")
					conn_to_server, err := quic.DialAddr(context.Background(), server_addr, tlsConf, generateQUICConfig())
					if err != nil {
						panic(err)
					}
					s.server_connection = conn_to_server
					fmt.Print("R: Connected to server\n")

					high_stream, err := s.server_connection.OpenStreamSyncWithPriority(
						context.Background(), priority_setting.HighPriority)
					if err != nil {
						panic(err)
					}
					s.server_stream_high_prio = high_stream

					low_stream, err := s.server_connection.OpenStreamSyncWithPriority(
						context.Background(), priority_setting.LowPriority)
					if err != nil {
						panic(err)
					}
					s.server_stream_low_prio = low_stream

					go s.passOnTraffic()
					go publishConnectionEstablished(conn)
				}

				s.connection_list = append(s.connection_list, conn)

				go streamAcceptWrapperRelay(conn, s)
			}

			// TODO add something to unsubscribe from the server (i.e. remove stream)

		}

	}()

	go keepConnectionsUpToDate(s)

	<-done
	fmt.Println("Relay done")

	return nil
}

func (s *RelayServer) changePriorityDropThreshold() {

	if len(s.connection_list) == 0 {
		fmt.Println("No connections to change priority drop limit")
		return
	}

	// TODO: maybe not load maps each time but only once in the beginning
	client_id, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/client_id", &ebpf.LoadPinOptions{})
	if err != nil {
		fmt.Println("Error loading client_id")
		panic(err)
	}
	client_data, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/client_data", &ebpf.LoadPinOptions{})
	if err != nil {
		panic(err)
	}

	for _, conn := range s.connection_list {
		ipaddr, port := getIPAndPort(conn)
		ipaddr_key := swapEndianness32(ipToInt32(ipaddr))
		port_key := swapEndianness16(port)

		key := client_key_struct{
			Ipaddr:  ipaddr_key,
			Port:    port_key,
			Padding: [2]uint8{0, 0},
		}
		id := &id_struct{}

		err = client_id.Lookup(key, id)
		if err != nil {
			fmt.Println("Error looking up client_id")
			panic(err)
		}

		client_info := &client_data_struct{}
		err = client_data.Lookup(id, client_info)
		if err != nil {
			fmt.Println("Error looking up client_data")
			panic(err)
		}

		// Since the priority 0 is encoding "NoPriority" we do modulo first
		// This way we loop from 1 to NumberOfPriorities instead of 0 to NumberOfPriorities-1
		client_info.PriorityDropLimit = (client_info.PriorityDropLimit % uint8(priority_setting.NumberOfPriorities)) + 1

		err = client_data.Update(id, client_info, ebpf.UpdateAny)
		if err != nil {
			fmt.Println("Error updating client_data")
			panic(err)
		}

		fmt.Println("R: Priority drop limit of stream is now", client_info.PriorityDropLimit)
	}

}

func (s *RelayServer) passOnTraffic() error {

	// listen for incoming streams
	streams_to_listen := []quic.Stream{s.server_stream_high_prio, s.server_stream_low_prio}
	for _, stream := range streams_to_listen {
		go func(stream quic.Stream) {
			for {
				buf := make([]byte, 1024) // TODO: larger buffer?
				n, err := stream.Read(buf)
				if err != nil {
					panic(err)
				}

				// buf, err := relay.server_connection.ReceiveDatagram(context.Background())
				// if err != nil {
				// 	panic(err)
				// }

				// fmt.Printf("%s", buf[:n])
				fmt.Printf("Relay got from server: %s\n", buf[:n])
				// fmt.Printf("Relay got from server: %s\nPassing on...\n", buf[:n])
				// for _, client := range relay.client_list {
				// 	send_stream := client.stream
				// 	_, err = send_stream.Write(buf[:n])
				// 	if err != nil {
				// 		panic(err)
				// 	}
				// }
			}
		}(stream)
	}

	// listen for incoming datagrams
	for {
		buf, err := s.server_connection.ReceiveDatagram(context.Background())
		if err != nil {
			panic(err)
		}

		fmt.Printf("Relay got from server: %s\n", buf)
		// fmt.Printf("Relay got from server: %s\nPassing on...\n", buf)
		// for _, client := range relay.client_list {
		// 	send_stream := client.stream
		// 	_, err = send_stream.Write(buf)
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// }
	}
}
