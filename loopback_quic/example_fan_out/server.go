package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
	"github.com/danielpfeifer02/quic-go-prio-packs/priority_setting"
	"github.com/danielpfeifer02/quic-go-prio-packs/qlog"
)

const server_addr = "192.168.10.1:4242"
const relay_addr = "192.168.11.2:4242"

var bpf_enabled = true

type pn_struct struct {
	Pn      uint16
	Changed uint8
	Padding [3]uint8
}

type id_struct struct {
	Id uint32
}

type client_key_struct struct {
	Ipaddr  uint32
	Port    uint16
	Padding [2]uint8
}

type client_data_struct struct {
	SrcMac            [6]uint8
	DstMac            [6]uint8
	SrcIp             uint32
	DstIp             uint32
	SrcPort           uint16
	DstPort           uint16
	ConnectionID      [16]uint8
	PriorityDropLimit uint8
	Padding           [3]uint8
}

type StreamingStream struct {
	stream     quic.Stream
	connection quic.Connection
}

type Server interface {
	run() error
}

type StreamingServer struct {
	conn_chan        chan quic.Connection
	stream_chan      chan quic.Stream
	interrupt_chan   chan bool
	stream_list      []quic.Stream
	high_prio_stream quic.Stream
	low_prio_stream  quic.Stream
}

var _ Server = &StreamingServer{}

func NewStreamingServer() *StreamingServer {
	return &StreamingServer{
		conn_chan:      make(chan quic.Connection),
		stream_chan:    make(chan quic.Stream),
		interrupt_chan: make(chan bool),
		stream_list:    make([]quic.Stream, 0),
		// TODO set high_prio_stream and low_prio_stream
		high_prio_stream: nil,
		low_prio_stream:  nil,
	}
}

func (s *StreamingServer) run() error {

	fmt.Println("Number of goroutines:", runtime.NumGoroutine())

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
				fmt.Println("S: New stream added")

			case conn := <-s.conn_chan:
				fmt.Println("S: New connection accepted")
				go streamAcceptWrapperServer(conn, s.stream_chan)
			}

			// TODO add something to unsubscribe from the server (i.e. remove stream)

		}

	}()

	<-done
	fmt.Println("Server done")

	return nil
}

func sendToAll(stream *quic.Stream, message string) {
	_, err := (*stream).Write([]byte(message))
	if err != nil {
		panic(err)
	}
}

func (s *StreamingServer) sendToAllHigh(message string) {
	// sendToAll(s.high_prio_stream, message)
	for _, stream := range s.stream_list {
		sendToAll(&stream, message)
	}
}

func (s *StreamingServer) sendToAllLow(message string) {
	// sendToAll(s.low_prio_stream, message)
}

type client_connection struct {
	conn   quic.Connection
	stream quic.Stream
}

type RelayServer struct {
	conn_chan         chan quic.Connection
	stream_chan       chan quic.Stream
	interrupt_chan    chan bool
	connection_list   []quic.Connection
	client_list       []client_connection
	connection_lookup map[quic.Stream]quic.Connection
	server_connection quic.Connection
	server_stream     quic.Stream
}

var _ Server = &RelayServer{}

// TODO check which maps are actually needed
func NewRelayServer() *RelayServer {
	return &RelayServer{
		conn_chan:         make(chan quic.Connection),
		stream_chan:       make(chan quic.Stream),
		interrupt_chan:    make(chan bool),
		connection_list:   make([]quic.Connection, 0),
		client_list:       make([]client_connection, 0),
		connection_lookup: make(map[quic.Stream]quic.Connection),
		server_connection: nil,
		server_stream:     nil,
	}
}

func (s *RelayServer) run() error {

	fmt.Println("Number of goroutines:", runtime.NumGoroutine())

	listener, err := quic.ListenAddr(relay_addr, generateTLSConfig(false), generateQUICConfig())
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
		if err != nil {
			panic(err)
		}

		id_counter, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/id_counter", &ebpf.LoadPinOptions{})
		if err != nil {
			panic(err)
		}
		err = id_counter.Update(uint32(0), uint32(0), 0)
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

	// ^ for testing purposes only
	go func(relay *RelayServer) {

		for {
			if len(relay.connection_list) > 0 {
				break
			}
			time.Sleep(1 * time.Second)
		}

		ipaddr, port := getIPAndPort(relay.connection_list[0])
		ipaddr_key := swapEndianness32(ipToInt32(ipaddr))
		port_key := swapEndianness16(port)

		key := client_key_struct{
			Ipaddr:  ipaddr_key,
			Port:    port_key,
			Padding: [2]uint8{0, 0},
		}
		id := &id_struct{}

		// TODO: maybe not load maps each time but only once in the beginning

		client_id, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/client_id", &ebpf.LoadPinOptions{})
		if err != nil {
			fmt.Println("Error loading client_id")
			panic(err)
		}
		err = client_id.Lookup(key, id)
		if err != nil {
			fmt.Println("Error looking up client_id")
			panic(err)
		}

		client_data, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/client_data", &ebpf.LoadPinOptions{})
		if err != nil {
			panic(err)
		}

		packet_counter, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/packet_counter", &ebpf.LoadPinOptions{})
		if err != nil {
			panic(err)
		}
		err = packet_counter.Update(uint32(0), uint32(0), 0)
		if err != nil {
			panic(err)
		}

		wait := time.Duration(4)

		for i := 0; i < 3; i++ { // TODO change packet_counter from 0 to 1 and back alternatingly
			time.Sleep(wait * time.Second)

			fmt.Println("\n\n\nSetting priority drop limit to 2 (i.e. dropping all packets since highest prio is 1)\n\n\n")
			client_info := &client_data_struct{}
			err = client_data.Lookup(id, client_info)
			if err != nil {
				fmt.Println("Error looking up client_data")
				panic(err)
			}
			client_info.PriorityDropLimit = 2
			err = client_data.Update(id, client_info, ebpf.UpdateAny)
			if err != nil {
				fmt.Println("Error updating client_data")
				panic(err)
			}

			packet_counter, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/packet_counter", &ebpf.LoadPinOptions{})
			if err != nil {
				panic(err)
			}
			err = packet_counter.Update(uint32(0), uint32(1), 0)
			if err != nil {
				panic(err)
			}

			time.Sleep(wait * time.Second)

			fmt.Println("\n\n\nSetting priority drop limit back to 0\n\n\n")
			err = client_data.Lookup(id, client_info)
			if err != nil {
				fmt.Println("Error looking up client_data")
				panic(err)
			}
			client_info.PriorityDropLimit = 0
			err = client_data.Update(id, client_info, ebpf.UpdateAny)
			if err != nil {
				fmt.Println("Error updating client_data")
				panic(err)
			}

			packet_counter, err = ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/packet_counter", &ebpf.LoadPinOptions{})
			if err != nil {
				panic(err)
			}
			err = packet_counter.Update(uint32(0), uint32(0), 0)
			if err != nil {
				panic(err)
			}

			// ! why does it not work without this?
			if i >= 1 {
				fmt.Printf("Sending info to client\n")
				for _, client_conn := range relay.client_list {
					send_stream := client_conn.stream
					_, err = send_stream.Write([]byte("You get the traffic again now!\n"))
					if err != nil {
						panic(err)
					}
				}
			}
		}
	}(s)

	// separate goroutine that handles all connections, interrupts and message sendings
	go func() {

		// TODO how to terminate correctly?
		go connectionAcceptWrapper(listener, s.conn_chan)

		for {

			select {

			case <-s.interrupt_chan:
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

				if s.server_stream == nil {
					if s.server_connection == nil {
						panic("Server connection not initialized")
					}
					server_stream, err := s.server_connection.OpenStreamSyncWithPriority(context.Background(), priority_setting.HighPriority)
					if err != nil {
						panic(err)
					}
					s.server_stream = server_stream
					go passOnTraffic(s)

					go publishConnectionEstablished()
				}

				fmt.Println("R: New stream added")

			case conn := <-s.conn_chan:

				// TODO: why ip address of bridge instead of client?
				ipaddr, port := getIPAndPort(conn)
				fmt.Printf("R: New connection accepted (from %s at port %d)\n", ipaddr.String(), port)

				if bpf_enabled {

					client_ctr++
					err = number_of_clients.Update(uint32(0), client_ctr, 0)
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

// ! TODO: weird behavior after prio dropped once?
func keepConnectionsUpToDate(relay *RelayServer) {

	client_data, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/client_data", &ebpf.LoadPinOptions{})
	if err != nil {
		panic(err)
	}
	client_id, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/client_id", &ebpf.LoadPinOptions{})
	if err != nil {
		panic(err)
	}

	for {

		for _, client_conn := range relay.client_list {

			ipaddr, port := getIPAndPort(client_conn.conn)
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
				panic(err)
			}

			client_info := &client_data_struct{}
			err = client_data.Lookup(id, client_info)
			if err != nil {
				panic(err)
			}

			active_conn_id := client_conn.conn.GetDestConnID(client_conn.stream)

			active_bytes := active_conn_id.Bytes()
			client_bytes := client_info.ConnectionID[:]
			different := active_conn_id.Len() != 16

			for i := 0; i < 16; i++ {
				if active_bytes[i] != client_bytes[i] {
					different = true
					break
				}
			}

			if different {
				fmt.Println("R: Connection ID changed. Updating...")
				copy(client_info.ConnectionID[:], active_conn_id.Bytes())
				err = client_data.Update(id, client_info, ebpf.UpdateAny)
				if err != nil {
					panic(err)
				}
			}

		}

		time.Sleep(4 * time.Second)

	}
}

func publishConnectionEstablished() {
	// time.Sleep(1 * time.Second)
	// if bpf_enabled {
	// 	connection_map, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/connection_established", &ebpf.LoadPinOptions{})
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	err = connection_map.Update(uint32(0), uint8(1), 0)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// }
}

func packetNumberHandler(conn quic.Connection) {

	client_pn, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/client_pn", &ebpf.LoadPinOptions{})
	if err != nil {
		panic(err)
	}

	ipaddr, port := getIPAndPort(conn)
	ipaddr_key := swapEndianness32(ipToInt32(ipaddr))
	port_key := swapEndianness16(port)
	key := client_key_struct{
		Ipaddr:  ipaddr_key,
		Port:    port_key,
		Padding: [2]uint8{0, 0},
	}
	val := &pn_struct{}

	old_val := int64(0)

	for {

		err := client_pn.Lookup(key, val)
		if err != nil {
			panic(err)
		}

		if val.Changed == 1 {
			fmt.Println("R: Packet number changed! Updating...")

			// TODO: change internal type to int32 since pn cannot be larger than 2^32?
			conn.SetPacketNumber(int64(val.Pn))

			// TODO: should I set it to the actual value or does this suffice?
			conn.SetHighestSent(old_val) // TODO: val.Pn - 1?

			val.Changed = 0
			err = client_pn.Update(key, val, 0)
			if err != nil {
				panic(err)
			}

			tmp := &pn_struct{}
			err := client_pn.Lookup(key, tmp)
			if err != nil {
				panic(err)
			}
			fmt.Printf("R: Updated packet number to %d (%d)\n", tmp.Pn, tmp.Changed)

		}

		old_val = int64(val.Pn)

	}
}

// create a global list of connection ids (i.e. 20 byte long byte arrays)
// when a new connection is initiated, add the connection id to the list
// when a connection is retired, remove the connection id from the list
// TODO: make list of lists based on ip port pair

// map with string as key and list of byte arrays as value
var connection_ids map[[6]byte][][]byte
var mutex = &sync.Mutex{}

func getConnectionIDsKey(qconn quic.Connection) [6]byte {
	ipaddr, port := getIPAndPort(qconn)
	ipv4 := ipaddr.To4()
	if ipv4 == nil {
		panic("Invalid IP address")
	}
	return [6]byte{ipv4[0], ipv4[1], ipv4[2], ipv4[3], byte(port >> 8), byte(port & 0xFF)}
}

func initConnectionId(id []byte, l uint8, conn packet_setting.QuicConnection) {

	fmt.Println("INIT")

	qconn := conn.(quic.Connection)

	if qconn.RemoteAddr().String() == server_addr {
		fmt.Println("Not initializing connection id for server")
		return
	}

	fmt.Println("Init connection id")

	key := getConnectionIDsKey(qconn)

	// if key does not exist, create new list
	mutex.Lock()
	if connection_ids == nil {
		connection_ids = make(map[[6]byte][][]byte)
	}
	if _, ok := connection_ids[key]; !ok {
		connection_ids[key] = make([][]byte, 0)
	}
	mutex.Unlock()

	connection_ids[key] = append(connection_ids[key], id)
}

func retireConnectionId(id []byte, l uint8, conn packet_setting.QuicConnection) {

	fmt.Println("RETIRE")

	qconn := conn.(quic.Connection)

	if qconn.RemoteAddr().String() == server_addr {
		fmt.Println("Not retiring connection id for server")
		return
	}

	fmt.Println("Retire connection id for connection:", qconn.RemoteAddr().String())

	key := getConnectionIDsKey(qconn)
	// remove from connection_ids
	for i, v := range connection_ids[key] {
		if string(v) == string(id) {
			connection_ids[key] = append(connection_ids[key][:i], connection_ids[key][i+1:]...)
			break
		}
	}

	go func(key [6]byte) {

		// it might be the case that retirements happen in the same packet as initiations
		// and that for a brief time there are no connection ids left
		// then: just wait until there are connection ids again
		// TODO: add failure after certain time
		for {
			if len(connection_ids[key]) > 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}

		if len(connection_ids[key]) == 0 {
			panic("No connection ids left")
		}

		// TODO: add connection to signature so that we can update the bpf map
		qconn := conn.(quic.Connection)

		updated := false
		for _, v := range connection_ids[key] {
			if true || v[0] == 0x01 {
				setBPFMapConnectionID(qconn, v)
				updated = true
				break
			}
		}
		if !updated {
			panic("No connection id with 0x01 found")
		}

		fmt.Println("Successfully retired connection id")
	}(key)
}

func updateConnectionId(id []byte, l uint8, conn packet_setting.QuicConnection) {

	fmt.Println("UPDATE")

	qconn := conn.(quic.Connection)

	if qconn.RemoteAddr().String() == server_addr {
		fmt.Println("Not updating connection id for server")
		return
	}
	setBPFMapConnectionID(qconn, id)
}

func setBPFMapConnectionID(qconn quic.Connection, v []byte) {
	ipaddr, port := getIPAndPort(qconn)
	ipaddr_key := swapEndianness32(ipToInt32(ipaddr))
	port_key := swapEndianness16(port)

	key := client_key_struct{
		Ipaddr:  ipaddr_key,
		Port:    port_key,
		Padding: [2]uint8{0, 0},
	}
	id := &id_struct{}

	// TODO: maybe not load maps each time but only once in the beginning

	client_id, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/client_id", &ebpf.LoadPinOptions{})
	if err != nil {
		fmt.Println("Error loading client_id")
		panic(err)
	}
	err = client_id.Lookup(key, id)
	if err != nil {
		fmt.Println("Error looking up client_id")
		panic(err)
	}

	client_data, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/client_data", &ebpf.LoadPinOptions{})
	if err != nil {
		fmt.Println("Error loading client_data")
		panic(err)
	}
	client_info := &client_data_struct{}
	err = client_data.Lookup(id, client_info)
	if err != nil {
		fmt.Println("Error looking up client_data")
		panic(err)
	}
	copy(client_info.ConnectionID[:], v)
	err = client_data.Update(id, client_info, ebpf.UpdateAny)
	if err != nil {
		fmt.Println("Error updating client_data")
		panic(err)
	}

	// fmt.Println("Successfully updated client_data for retired connection id")
	// fmt.Printf("Priority drop limit of stream is %d\n", client_info.PriorityDropLimit)
}

func incrementPacketNumber(pn int64, conn packet_setting.QuicConnection) {

	fmt.Println("INCREMENT")

	qconn := conn.(quic.Connection)

	if qconn.RemoteAddr().String() == server_addr {
		fmt.Println("Not incrementing pn for server")
		return
	}
	fmt.Println("Increased packet number", qconn.RemoteAddr().String())

	new_pn := pn_struct{
		Pn:      uint16(pn + 1),
		Changed: uint8(0),
		Padding: [3]uint8{0, 0, 0},
	}

	ipaddr, port := getIPAndPort(qconn)
	key := client_key_struct{
		Ipaddr:  swapEndianness32(ipToInt32(ipaddr)),
		Port:    swapEndianness16(uint16(port)),
		Padding: [2]uint8{0, 0},
	}

	client_pn, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/client_pn", &ebpf.LoadPinOptions{})
	if err != nil {
		panic(err)
	}
	err = client_pn.Update(key, new_pn, 0)
	if err != nil {
		fmt.Println("Error updating client_pn")
		panic(err)
	}

	fmt.Println("Client packet number map updated")

}

func getIPAndPort(conn quic.Connection) (net.IP, uint16) {
	tup := strings.Split(conn.RemoteAddr().String(), ":")
	ipaddr := net.ParseIP(tup[0])
	if ipaddr == nil {
		panic("Invalid IP address")
	}
	port, err := strconv.Atoi(tup[1])
	if err != nil {
		panic(err)
	}
	return ipaddr, uint16(port)
}

// TODO this is probably not the most elegant way to clear the BPF maps
func clearBPFMaps() {

	paths := []string{"client_data",
		"client_id",
		"id_counter",
		"number_of_clients",
		"connection_established",
		"packet_counter",
		"client_pn"}
	map_location := "/sys/fs/bpf/tc/globals/"

	for _, path := range paths {
		cmd := exec.Command("./clear_bpf_map", map_location+path)
		stdout, err := cmd.Output()
		if err != nil {
			fmt.Printf(string(stdout))
			panic(err)
		}
		fmt.Println(string(stdout))
	}
}

func ipToInt32(ip net.IP) uint32 {
	ip = ip.To4() // Convert to IPv4
	if ip == nil {
		panic("Trying to convert an invalid IPv4 address")
	}
	// Convert IPv4 address to integer
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func swapEndianness16(val uint16) uint16 {
	return (val&0xFF)<<8 | (val&0xFF00)>>8
}

func swapEndianness32(val uint32) uint32 {
	return (val&0xFF)<<24 | (val&0xFF00)<<8 | (val&0xFF0000)>>8 | (val&0xFF000000)>>24
}

func passOnTraffic(relay *RelayServer) error {
	for {
		buf := make([]byte, 1024)
		n, err := relay.server_stream.Read(buf)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Relay got from server: %s\n(This is just for ACK creation!)\n", buf[:n])
		// fmt.Printf("Relay got from server: %s\nPassing on...\n", buf[:n])
		// for _, send_stream := range relay.stream_list {
		// 	_, err = send_stream.Write(buf[:n])
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// }
	}
}

func connectionAcceptWrapper(listener *quic.Listener, channel chan quic.Connection) {
	for {
		fmt.Println("before")
		conn, err := listener.Accept(context.Background())
		fmt.Println("after")
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

// Setup a bare-bones TLS config for the server
func generateTLSConfig(klf bool) *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	if !klf {
		return &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			NextProtos:   []string{"quic-streaming-example"},
			CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256},
		}
	}

	// Create a KeyLogWriter
	keyLogFile, err := os.OpenFile("tls.keylog", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	// defer keyLogFile.Close() // TODO why not close?

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-streaming-example"},
		KeyLogWriter: keyLogFile,
		CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256},
	}
}

func generateQUICConfig() *quic.Config {
	return &quic.Config{
		Tracer:         qlog.DefaultTracer,
		MaxIdleTimeout: 5 * time.Minute,
	}
}
