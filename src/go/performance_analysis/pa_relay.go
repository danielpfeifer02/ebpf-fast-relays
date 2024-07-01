package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"common.com/common"
	"github.com/danielpfeifer02/quic-go-prio-packs"
)

func relay() {

	if bpf_enabled {

		common.InitializeCacheSetup()

		// 0. Load all the maps
		common.LoadBPFMaps()

		// 1. Clearing the BPF maps
		common.ClearBPFMaps()

	}

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

	if bpf_enabled {
		// TODO: what else needs to be done to make sure the bpf program works with this setup?

		// 2. Set number_of_clients and id_counter to 0
		client_ctr := uint32(1)
		err = common.Number_of_clients.Update(uint32(0), client_ctr, 0)
		if err != nil {
			panic(err)
		}

		// 3. Set id counter to 0
		err = common.Id_counter.Update(uint32(0), uint32(0), 0)
		if err != nil {
			panic(err)
		}

		// 4. Start the routing to register BPF packets
		go common.RegisterBPFPacket(client_conn)

		// 5. Set connection as established
		ip, port := common.GetIPAndPort(client_conn, true)
		err = common.SetConnectionEstablished(ip, port)
		if err != nil {
			panic(err)
		}

		// 6. Set bpf handlers
		setBPFHandlers()

		// (x. Increment number_of_client counter for new clients - not needed since we only have one client)
	}

	if use_datagrams {
		// TODO: datagram setup doesn't make sense with end notification also being a datagram
		relay_datagram_handling(server_conn, client_conn, ctx)
	} else {
		end_chan := make(chan struct{})
		go func() {
			var dtg []byte
			for {
				dtg, err = server_conn.ReceiveDatagram(ctx)
			if err != nil {
				fmt.Println("Error receiving datagram from server")
				panic(err)
				}
				if string(dtg) == "END" {
					fmt.Println("Received END datagram from server")
					break
				} else {
					fmt.Println("Received unexpected datagram from server", string(dtg))
				}
			}
			fmt.Println("Received END datagram from server")
			for i := 0; i < 10; i++ {
				client_conn.SendDatagram([]byte(fmt.Sprintf("END%d", i)))
			}
			time.Sleep(1 * time.Second)
			os.Exit(0)
			time.Sleep(100 * time.Millisecond)
			end_chan <- struct{}{}
		}()

		relay_stream_handling(server_conn, client_conn, ctx, end_chan)
	}
}

func relay_stream_handling(server_conn, client_conn quic.Connection, ctx context.Context, end_chan chan struct{}) {
	ts_buffer := make([]byte, payload_length)

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

			if forwarding_enabled {
				// Send to client
				client_str, err := client_conn.OpenUniStream() //WithPriority(priority_setting.HighPriority)
				if err != nil {
					fmt.Println("Error opening stream to client")
					panic(err)
				}
				packet_setting.DebugPrintln("Stream id to client:", client_str.StreamID())
				// defer client_str.Close()

				if ts_buffer[0] != 0 {
					panic("First byte is not 0")
				}
				ts_buffer[0] = ts_buffer[0] | USERSPACE_FLAG
				_, err = client_str.Write(ts_buffer[:n])
				if err != nil {
					fmt.Println("Error writing to client")
					panic(err)
				}
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
