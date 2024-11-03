package common

// TODO: add everything here that is used for the video example as well as for the performance analysis

// TODO: change all calls from the examples from bpf_handler.go to here

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
)

const (
	NO_CHANGE = iota
	INCREASE
	DECREASE
)

// This function will clear all BPF maps once the relay is started.
// This relies on an external C program since there exist wrappers
// to iterate over keys of a map.
// Ideally this would also be done in Go.
// TODO: not the most elegant way to clear the BPF maps
func ClearBPFMaps() {

	// TODO: do with ebpf library

	paths := []string{
		"client_data",
		"client_id",
		"id_counter",
		"number_of_clients",
		"client_pn",
		"connection_current_pn",
		"connection_pn_translation",
		"connection_unistream_id_counter",
		"connection_unistream_id_translation",
		"client_stream_offset",
		"unistream_id_is_retransmission"}
	map_location := "/sys/fs/bpf/tc/globals/"

	for _, path := range paths {
		cmd := exec.Command("../../utils/build/clear_bpf_map", map_location+path)
		stdout, err := cmd.Output()
		if err != nil {
			fmt.Println(string(stdout))
			panic(err)
		}
		fmt.Println(string(stdout))
	}
}

// Create a global list of connection ids (i.e. <20 byte long byte arrays)
// when a new connection is initiated, add the connection id to the list
// when a connection is retired, remove the connection id from the list

// This map stores the connection ids given a key that consists of the
// IP address and port of a connection.
var connection_ids map[[6]byte][][]byte

// We need a lock for the global list since the
// underlying connection management is concurrent.
var mutex = &sync.Mutex{}

// This function is called from within the underlying QUIC implementation
// when a new connection is initiated. It will then be added to the global
// connection_id list.
func InitConnectionId(id []byte, l uint8, conn packet_setting.QuicConnection) {

	qconn := conn.(quic.Connection)

	if qconn.RemoteAddr().String() == packet_setting.SERVER_ADDR {
		// We do only add connection ids for client connections.
		return
	}
	debugPrint("INIT")
	debugPrint("Initialize connection id for connection:", qconn.RemoteAddr().String())

	key := getConnectionIDsKey(qconn)

	// If the key does not exist, create new list.
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

// This function is called when a connection is retired.
// The connection id is removed from the global list.
func RetireConnectionId(id []byte, l uint8, conn packet_setting.QuicConnection) {

	if len(id) == 0 {
		fmt.Println("Empty connection id???")
		return
	}

	qconn := conn.(quic.Connection)

	if qconn.RemoteAddr().String() == packet_setting.SERVER_ADDR {
		// We only consider connection ids for client connections.
		return
	}
	debugPrint("RETIRE")
	debugPrint("Retire connection id for connection:", qconn.RemoteAddr().String())

	retired_priority := id[0]

	key := getConnectionIDsKey(qconn)
	for i, v := range connection_ids[key] {
		if string(v) == string(id) {
			connection_ids[key] = append(connection_ids[key][:i], connection_ids[key][i+1:]...)
			break
		}
	}

	go func(key [6]byte) {

		// It might be the case that retirements happen in the same packet as initiations
		// and that for a brief time there are no connection ids left.
		// If that is the case just wait until there are connection ids again.
		// If nothing happens after 100 iterations (i.e. 1 second), panic.
		for i := 0; i < 100; i++ {
			if len(connection_ids[key]) > 0 {
				break
			}
			// <-time.After(10 * time.Millisecond)
			time.Sleep(10 * time.Millisecond) // TODO: Sleep or After?
		}

		if len(connection_ids[key]) == 0 {
			panic("No connection ids left")
		}

		qconn := conn.(quic.Connection)

		// TODO: is this correct?
		// TODO: this function does not seem to be called
		// TODO: in the example.
		updated := false
		for _, v := range connection_ids[key] {
			if v[0] == retired_priority {
				SetBPFMapConnectionID(qconn, v)
				updated = true
				break
			}
		}
		if !updated {
			panic("No connection id with the retired priority found!")
		}

		debugPrint("Successfully retired connection id")
	}(key)
}

// This function is called from within the underlying QUIC implementation
// when a connection id is updated.
// It sets the current connection id to the provided one.
func UpdateConnectionId(id []byte, l uint8, conn packet_setting.QuicConnection) {

	qconn := conn.(quic.Connection)

	if qconn.RemoteAddr().String() == packet_setting.SERVER_ADDR {
		// We only consider connection ids for client connections.
		return
	}

	debugPrint("UPDATE")
	SetBPFMapConnectionID(qconn, id)
}

// TODO: mabye split up into a "get client data" function
func SetBPFMapConnectionID(qconn quic.Connection, v []byte) {
	ipaddr, port := GetIPAndPort(qconn, true)
	ipaddr_key := swapEndianness32(ipToInt32(ipaddr))
	port_key := swapEndianness16(port)

	key := client_key_struct{
		Ipaddr:  ipaddr_key,
		Port:    port_key,
		Padding: [2]uint8{0, 0},
	}
	id := &id_struct{}

	// This should not occur since the function pointers should only be set if
	// bpf is enabled.
	// Still to make sure that the program does not panic, we check if bpf is enabled.
	if !true {
		fmt.Println("BPF not enabled. Cannot access maps.")
		return
	}

	debugPrint("ipaddr", ipaddr, "port", port)

	err := Client_id.Lookup(key, id)
	if err != nil {
		fmt.Println("Error looking up client_id")
		panic(err)
	}

	client_info := &client_data_struct{}
	err = Client_data.Lookup(id, client_info)
	if err != nil {
		fmt.Println("Error looking up client_data")
		panic(err)
	}
	copy(client_info.ConnectionID[:], v)
	err = Client_data.Update(id, client_info, ebpf.UpdateAny)
	if err != nil {
		fmt.Println("Error updating client_data")
		panic(err)
	}

	debugPrint("Successfully updated client_data for retired connection id")
	debugPrint("Priority drop limit of stream is", client_info.PriorityDropLimit)
}

// This function is called from within the underlying QUIC implementation
// and is used when an ack packet number is re-translated (since the
// relay userspace only gets ACKs for packet numbers which have been changed
// by the bpf program).
func TranslateAckPacketNumber(pn int64, conn packet_setting.QuicConnection) (int64, error) {

	qconn := conn.(quic.Connection)

	if qconn.RemoteAddr().String() == packet_setting.SERVER_ADDR {
		// We only consider connection ids for client connections.
		return pn, nil
	}
	debugPrint("TRANSLATE", pn)
	debugPrint("Translated packet number", qconn.RemoteAddr().String())

	ipaddr, port := GetIPAndPort(qconn, true)
	client_key := client_key_struct{
		Ipaddr:  swapEndianness32(ipToInt32(ipaddr)),
		Port:    swapEndianness16(uint16(port)),
		Padding: [2]uint8{0, 0},
	}
	key := client_pn_map_key{
		Key: client_key,
		Pn:  uint32(pn),
	}

	val := &connnection_pn_stuct{}
	err := Connection_pn_translation.Lookup(key, val)
	if err != nil {
		debugPrint("No entry for ", pn)
		return 0, fmt.Errorf("no entry for %d", pn)
	}

	debugPrint(pn, "->", val.Pn)

	translated_pn := int64(val.Pn)
	debugPrint(translated_pn)
	return translated_pn, nil
}

// This function is necessary to keep the bpf map from overflowing with
// too many packet number translations.
// The function is called from within the underlying QUIC implementation
// and deletes the translation for a packet number once it has been seen
// by the relay userspace (where it will be cached somewhere else).
// To check the number of mappings inside of a bpf map you can use the
// following command:
// bpftool map dump name connection_pn_t -j | jq ". | length"
func DeleteAckPacketNumberTranslation(pn int64, conn packet_setting.QuicConnection) {

	qconn := conn.(quic.Connection)

	if qconn.RemoteAddr().String() == packet_setting.SERVER_ADDR {
		// We only consider connection ids for client connections.
		return
	}
	debugPrint("DELETE", pn)
	debugPrint("Deleted translation for packet from", qconn.RemoteAddr().String())

	ipaddr, port := GetIPAndPort(qconn, true)
	client_key := client_key_struct{
		Ipaddr:  swapEndianness32(ipToInt32(ipaddr)),
		Port:    swapEndianness16(uint16(port)),
		Padding: [2]uint8{0, 0},
	}
	key := client_pn_map_key{
		Key: client_key,
		Pn:  uint32(pn),
	}

	err := Connection_pn_translation.Delete(key)
	if err != nil {
		return
	}

	debugPrint("Successfully deleted translation")
}

func GetLargestSentPacketNumber(conn packet_setting.QuicConnection) int64 {

	qconn := conn.(quic.Connection)

	ipaddr, port := GetIPAndPort(qconn, true)
	ipaddr_key := swapEndianness32(ipToInt32(ipaddr))
	port_key := swapEndianness16(port)

	key := client_key_struct{
		Ipaddr:  ipaddr_key,
		Port:    port_key,
		Padding: [2]uint8{0, 0},
	}

	current_pn := &connnection_pn_stuct{}
	err := Connection_current_pn.Lookup(key, current_pn)
	if err != nil {
		fmt.Println("Error looking up connection_current_pn")
		panic(err)
	}

	return int64(current_pn.Pn - 1)
}

// This function is used for registering the packets that have been sent by the
// BPF program.
func RegisterBPFPacket(conn quic.Connection) { // TODO: make more efficient with ringbuffer bpf map

	go func() {

		ipaddr, port := GetIPAndPort(conn, true)
		key := client_key_struct{
			Ipaddr:  swapEndianness32(ipToInt32(ipaddr)),
			Port:    swapEndianness16(port),
			Padding: [2]uint8{0, 0},
		}

		current_pn := &connnection_pn_stuct{}
		for {

			err := Connection_current_pn.Lookup(key, current_pn)
			if err == nil {
				break
			}
			conn.SetHighestSent(int64(current_pn.Pn) - 1)

		}
	}()

	max_register_queue_size := 1 << 11 // 2048
	val := &packet_register_struct{}
	current_index := index_key_struct{
		Index: 0,
	}

	fmt.Println("Start registering packets...")

	// TODO: move to common
	perfMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/packet_events", nil)
	if err != nil {
		fmt.Println("Error loading perf map")
		panic(err)
	}
	pack_to_reg_rb_reader, err := ringbuf.NewReader(perfMap)
	if err != nil {
		fmt.Println("Error creating ringbuffer reader")
		panic(err)
	}

	// TODO: remove before final version
	use_lookup := false // TODO: for easy performance comparison
	var record *ringbuf.Record = &ringbuf.Record{}

skip_retrieval:
	for {

		// print size of ringbuffer
		// fmt.Println("Size of ringbuffer:", pack_to_reg_rb_reader.BufferSize())

		// TODO: add same changes to common and other Lookup examples
		if !use_lookup {
			// TODO: instead of sleep, use (if there is) a cheap way to find out if map changed
			err := pack_to_reg_rb_reader.ReadInto(record) // TODO: ReadInto to reuse memory?
			// err := error(nil)
			if err != nil {
				fmt.Println("Error reading from ringbuffer")
				panic(err)
			}

			if len(record.RawSample) < 29 {
				panic("Record too short")
			}
			// fmt.Println("Record:", len(record.RawSample))
			val = &packet_register_struct{
				PacketNumber: binary.LittleEndian.Uint64(record.RawSample[0:8]),
				SentTime:     binary.LittleEndian.Uint64(record.RawSample[8:16]),
				Length:       binary.LittleEndian.Uint64(record.RawSample[16:24]),
				Offset:       binary.LittleEndian.Uint64(record.RawSample[24:32]),
				ServerPN:     binary.LittleEndian.Uint32(record.RawSample[32:36]),
				Flags:        binary.LittleEndian.Uint32(record.RawSample[36:40]),
			}

			// if val.PacketNumber <= 39 && val.PacketNumber >= 30 {
			// 	fmt.Println("Packet number", val.PacketNumber, "at time", time.Now().UnixNano())
			// }

			// fmt.Printf("Loaded %d bytes from ringbuffer\n", len(record.RawSample))

		} else {
			time.Sleep(1 * time.Millisecond) // TODO: Sleep or After?
			// Check if there are packets to register
			err = Packets_to_register.Lookup(current_index, val)
		}

		valid := val.Flags&packet_setting.VALID_FLAG > 0
		userspace := val.Flags&packet_setting.USERSPACE_FLAG > 0
		retransmission := val.Flags&packet_setting.RETRANSMISSION_FLAG > 0

		if err == nil && valid { // TODO: why not valid?

			// fmt.Println("Read into record: ", val.PacketNumber, val.SentTime, val.Length, val.ServerPN, val.Valid, val.SpecialRetransmission)

			// TODO: this as go routine causes A LOT of go routines. is there any benefit?
			// go func(val packet_register_struct, idx index_key_struct, mp *ebpf.Map) { // TODO: speed up when using goroutines?

			var server_pack packet_setting.RetransmissionPacketContainer = packet_setting.RetransmissionPacketContainer{
				Valid:   true,
				RawData: nil,
			}

			// We only need to retrieve the server packet if it is indeed a packet from the server.
			// Packets from the relay are handled normally.
			if true { // TODO: turn back on (not sure what this is)
				for i := 0; i < 1_000; i++ { // TODO: whats a good limit?
					if !userspace && !retransmission { // Server packet
						server_pack = RetreiveServerPacket(int64(val.ServerPN))
					} else if retransmission { // Userspace / retransmission packet
						fmt.Println("Try reading relay stored packet")
						server_pack = RetreiveRelayPacket(int64(val.ServerPN))
					} else {
						fmt.Println("'Real' userspace packet")
						// TODO: handle real userspace packets here as well?
						goto skip_retrieval
					}
					if server_pack.Valid {
						break
					}
					// <-time.After(1 * time.Millisecond) // TODO: optimal?
					time.Sleep(10 * time.Microsecond) // TODO: Sleep or After?
				}
				if !server_pack.Valid {
					fmt.Println("No server packet found for packet number", val.ServerPN)
					// continue //
					panic("No server packet found")
				}
			} else {
				// In case the packet originated in the relay already we only need to update the packet number
				// since it is already registered.

				packet_number_mapping := packet_setting.PacketNumberMapping{
					OriginalPacketNumber: int64(val.ServerPN),
					NewPacketNumber:      int64(val.PacketNumber),
				}
				conn.UpdatePacketNumberMapping(packet_number_mapping)

				// continue // TODO why was this here?

				// for i := 0; i < 1_000; i++ { // TODO: whats a good limit?
				// 	server_pack = RetreiveRelayPacket(int64(val.ServerPN))
				// 	if server_pack.Valid {
				// 		break
				// 	}
				// 	// <-time.After(1 * time.Millisecond) // TODO: optimal?
				// 	time.Sleep(10 * time.Microsecond) // TODO: Sleep or After?
				// }
			}

			// if server_pack.Length != int64(val.Length) { // TODO: useful check?
			// 	fmt.Println(server_pack.Length, val.Length)
			// 	panic("Lengths do not match")
			// }

			// diff := uint64(time.Now().UnixNano()) - val.SentTime
			// fmt.Println("Diff:", diff, "Val.SentTime:", val.SentTime)

			// TODO: at this point we need to have the raw data of the packet
			if len(server_pack.RawData) == 0 {
				panic("No raw data found")
			}

			// fmt.Println("Offset be like:", val.Offset, "Packet number be like:", val.PacketNumber)

			packet := packet_setting.PacketRegisterContainerBPF{
				PacketNumber: int64(val.PacketNumber),
				SentTime:     int64(val.SentTime),
				Length:       int64(val.Length), // TODO: length needed if its in server_pack?
				Offset:       int64(val.Offset),

				RawData: server_pack.RawData,

				// These two will be set in the wrapper of the quic connection.
				Frames:       nil,
				StreamFrames: nil,
			}

			conn.RegisterBPFPacket(packet)
			// fmt.Println("Registered packet")

			// Set valid to 0 to indicate that the packet has been registered
			val.Flags = val.Flags & ^packet_setting.VALID_FLAG
			err = Packets_to_register.Update(current_index, val, ebpf.UpdateAny)
			if err != nil {
				fmt.Println("Error updating buffer map")
				panic(err)
			}

			// TODO: this as go routine causes A LOT of go routines. is there any benefit?
			// }(*val, current_index, Packets_to_register) // this pass by copy is necessary since the goroutine might be executed after the next iteration

			current_index.Index = uint32((current_index.Index + 1) % uint32(max_register_queue_size))
		} else if err == nil {
			fmt.Println("Packet not valid?") //, err, val.Valid)
		}

	}
}

func SetConnectionEstablished(ip net.IP, port uint16) error {

	key := client_key_struct{
		Ipaddr:  swapEndianness32(ipToInt32(ip)),
		Port:    swapEndianness16(uint16(port)),
		Padding: [2]uint8{0, 0},
	}

	est := &established_val_struct{
		Established: uint8(1),
	}

	err := Connection_established.Update(key, est, ebpf.UpdateAny)
	if err != nil {
		fmt.Println("Error updating established", err)
		return err
	}

	fmt.Println("Connection established for", ip, ":", port)
	return nil
}

func MarkStreamIdAsRetransmission(stream_id uint64, conn packet_setting.QuicConnection) { // TODO: stream id alone seems not enough - pn + connection id + stream id instead?

	qconn := conn.(quic.Connection)

	ipaddr, port := GetIPAndPort(qconn, true)
	ipaddr_key := swapEndianness32(ipToInt32(ipaddr))
	port_key := swapEndianness16(port)

	key := unistream_id_retransmission_struct{
		IpAddr:   ipaddr_key,
		Port:     port_key,
		Padding:  [2]uint8{0, 0},
		StreamId: stream_id,
	}

	retrans := &retransmission_val_struct{
		IsRetransmission: uint8(1),
	}

	err := Unistream_id_is_retransmission.Update(key, retrans, ebpf.UpdateAny)
	if err != nil {
		fmt.Println("Error updating unistream_id_is_retransmission")
		panic(err)
	}

	// fmt.Println("Marked stream id as retransmission", key.IpAddr, key.Port, key.StreamId)

}

func MarkPacketAsRetransmission(packet_id packet_setting.PacketIdentifierStruct) {

	if packet_id.ConnectionIDLen != 16 {
		panic("Connection ID length not 16")
	}
	conn_id_bytes := [16]uint8(packet_id.ConnectionID[:16]) // TODO: why so cursed?

	key := packet_is_retransmission_struct{
		StreamID:     packet_id.StreamID,
		PacketNumber: (uint32)(packet_id.PacketNumber),
		ConnectionID: conn_id_bytes,
		Padding:      [4]uint8{0, 0, 0, 0},
	}

	retrans := &retransmission_val_struct{
		IsRetransmission: uint8(1),
	}

	err := Packet_is_retransmission.Update(key, retrans, ebpf.UpdateAny)
	if err != nil {
		fmt.Println("Error updating packet_is_retransmission")
		panic(err)
	}

}

var already_started_printing = false // TODO: not the most elegant way to do this
var last_data *packet_setting.CongestionWindowData = nil
var last_data_mutex = &sync.Mutex{}

func HandleCongestionMetricUpdate(data packet_setting.CongestionWindowData, conn packet_setting.QuicConnection) {

	if conn == nil {
		return // Could be the case in the beginning before the connection is set everywhere
	}
	qconn := conn.(quic.Connection)

	if qconn.RemoteAddr().String() == packet_setting.SERVER_ADDR {
		// We only consider connection ids for client connections.
		return
	}

	ipaddr, port := GetIPAndPort(qconn, true)
	ipaddr_key := swapEndianness32(ipToInt32(ipaddr))
	port_key := swapEndianness16(port)

	key := client_key_struct{
		Ipaddr:  ipaddr_key,
		Port:    port_key,
		Padding: [2]uint8{0, 0},
	}

	last_data_mutex.Lock()
	last_data = &data
	last_data_mutex.Unlock()
	if !already_started_printing && packet_setting.RELAY_CWND_DATA_PRINT {
		go startPrintCongestionWindowDataThread()
		already_started_printing = true
	}

	client_id := &id_struct{}
	err := Client_id.Lookup(key, client_id)
	if err != nil {
		fmt.Println("Error looking up client_id")
		fmt.Println("When booting this can occur if the connection is not yet been set up fully")
		return
	}

	client_data := &client_data_struct{}
	err = Client_data.Lookup(client_id, client_data)
	if err != nil {
		fmt.Println("Error looking up client_data")
		panic(err)
	}

	neededChange := calculateNeededChangeOfPriorityDropLimit(data, client_data)
	if neededChange == NO_CHANGE {
		return
	}

	UnitChangePriorityDropLimit(client_id.Id, neededChange == INCREASE)

}

func calculateNeededChangeOfPriorityDropLimit(data packet_setting.CongestionWindowData, client_data *client_data_struct) int {

	// TODO: add logic to determine if change is needed
	return NO_CHANGE

}

func UnitChangePriorityDropLimit(c_id uint32, increment bool) error {

	id := &id_struct{
		Id: c_id,
	}

	client_info := &client_data_struct{}
	err := Client_data.Lookup(id, client_info)
	if err != nil {
		fmt.Println("Error looking up client_data")
		return err
	}

	if client_info.PriorityDropLimit == 0 {
		return nil
	}

	if increment {
		client_info.PriorityDropLimit++
	} else {
		client_info.PriorityDropLimit--
	}

	err = Client_data.Update(id, client_info, ebpf.UpdateAny)
	if err != nil {
		fmt.Println("Error updating client_data")
		return err
	}

	debugPrint("Successfully updated client_data for retired connection id")
	return nil
}

func ChangePriorityDropLimit(c_id uint32, limit uint8) error {

	id := &id_struct{
		Id: c_id,
	}

	client_info := &client_data_struct{}
	err := Client_data.Lookup(id, client_info)
	if err != nil {
		fmt.Println("Error looking up client_data")
		return err
	}

	client_info.PriorityDropLimit = limit

	err = Client_data.Update(id, client_info, ebpf.UpdateAny)
	debugPrint("Update at point nr.", 11)
	if err != nil {
		fmt.Println("Error updating client_data")
		return err
	}

	debugPrint("Successfully updated client_data for retired connection id")
	return nil

}

func startPrintCongestionWindowDataThread() {
	for {
		num_of_routines := runtime.NumGoroutine()
		last_data_mutex.Lock()
		fmt.Println("+-----------------------------------------------+")
		fmt.Println("|\tCongestion window data (", num_of_routines, ")\t\t|")
		fmt.Println("+-----------------------------------------------+")
		fmt.Println("|\tMinRTT:\t\t\t", last_data.MinRTT, "\t|")
		fmt.Println("|\tSmoothedRTT:\t\t", last_data.SmoothedRTT, "\t|")
		fmt.Println("|\tLatestRTT:\t\t", last_data.LatestRTT, "\t|")
		fmt.Println("|\tRTTVariance:\t\t", last_data.RTTVariance, "\t\t|")
		fmt.Println("|\tCongestionWindow:\t", last_data.CongestionWindow, "\t\t|")
		fmt.Println("|\tBytesInFlight:\t\t", last_data.BytesInFlight, "\t|")
		fmt.Println("|\tPacketsInFlight:\t", last_data.PacketsInFlight, "\t\t|")
		fmt.Println("+-----------------------------------------------+")
		last_data_mutex.Unlock()
		time.Sleep(1 * time.Second)
	}
}
