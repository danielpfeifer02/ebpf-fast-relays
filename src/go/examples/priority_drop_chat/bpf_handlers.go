package main

import (
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
)

func publishConnectionEstablished(conn quic.Connection) {
	time.Sleep(1 * time.Second)
	if bpf_enabled {
		connection_map, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/connection_established", &ebpf.LoadPinOptions{})
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
		estab := &conn_established_struct{
			Established: uint8(1),
		}
		err = connection_map.Update(key, estab, 0)
		debugPrint("Update at point nr.", 10)
		if err != nil {
			panic(err)
		}
		fmt.Println("R: Connection established")
	}
}

func packetNumberHandler(conn quic.Connection) {

	// client_pn, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/client_pn", &ebpf.LoadPinOptions{})
	connection_current_pn, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/connection_current_pn", &ebpf.LoadPinOptions{})
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
	val := &connnection_pn_stuct{}

	// old_val := int64(0)

	for {

		err = connection_current_pn.Lookup(key, val)
		if err == nil && val.Pn > 0 {
			conn.SetHighestSent(int64(val.Pn) - 1)
			// fmt.Println(val.Pn - 1)
		}

		// err := client_pn.Lookup(key, val)
		// if err != nil {
		// 	panic(err)
		// }

		// if val.Changed == 1 {
		// 	fmt.Println("R: Packet number changed! Updating...")

		// 	// TODO: change internal type to int32 since pn cannot be larger than 2^32?
		// 	conn.SetPacketNumber(int64(val.Pn))

		// 	// TODO: should I set it to the actual value or does this suffice?
		// 	conn.SetHighestSent(old_val) // TODO: val.Pn - 1?

		// 	val.Changed = 0
		// 	err = client_pn.Update(key, val, 0)
		// 	if err != nil {
		// 		panic(err)
		// 	}

		// 	tmp := &pn_struct{}
		// 	err := client_pn.Lookup(key, tmp)
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// 	fmt.Printf("R: Updated packet number to %d (%d)\n", tmp.Pn, tmp.Changed)

		// }

		// old_val = int64(val.Pn)

	}
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
				debugPrint("R: Connection ID changed. Updating...")
				copy(client_info.ConnectionID[:], active_conn_id.Bytes())
				err = client_data.Update(id, client_info, ebpf.UpdateAny)
				debugPrint("Update at point nr.", 9)
				if err != nil {
					panic(err)
				}
			}

		}

		time.Sleep(4 * time.Second)

	}
}

// create a global list of connection ids (i.e. 20 byte long byte arrays)
// when a new connection is initiated, add the connection id to the list
// when a connection is retired, remove the connection id from the list
// TODO: make list of lists based on ip port pair

// map with string as key and list of byte arrays as value
var connection_ids map[[6]byte][][]byte
var mutex = &sync.Mutex{}

func initConnectionId(id []byte, l uint8, conn packet_setting.QuicConnection) {

	qconn := conn.(quic.Connection)

	if qconn.RemoteAddr().String() == server_addr {
		// fmt.Println("Not initializing connection id for server")
		return
	}
	debugPrint("INIT")
	debugPrint("Init connection id")

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

	qconn := conn.(quic.Connection)

	if qconn.RemoteAddr().String() == server_addr {
		// fmt.Println("Not retiring connection id for server")
		return
	}
	debugPrint("RETIRE")
	debugPrint("Retire connection id for connection:", qconn.RemoteAddr().String())

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

		debugPrint("Successfully retired connection id")
	}(key)
}

func updateConnectionId(id []byte, l uint8, conn packet_setting.QuicConnection) {

	qconn := conn.(quic.Connection)

	if qconn.RemoteAddr().String() == server_addr {
		// fmt.Println("Not updating connection id for server")
		return
	}
	debugPrint("UPDATE")
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
	debugPrint("Update at point nr.", 11)
	if err != nil {
		fmt.Println("Error updating client_data")
		panic(err)
	}

	debugPrint("Successfully updated client_data for retired connection id")
	debugPrint("Priority drop limit of stream is", client_info.PriorityDropLimit)
}

func incrementPacketNumber(pn int64, conn packet_setting.QuicConnection) {

	debugPrint("INCREMENT")

	qconn := conn.(quic.Connection)

	if qconn.RemoteAddr().String() == server_addr {
		// fmt.Println("Not incrementing pn for server")
		return
	}
	debugPrint("Increased packet number", qconn.RemoteAddr().String())

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
	debugPrint("Update at point nr.", 12)
	if err != nil {
		fmt.Println("Error updating client_pn")
		panic(err)
	}

	debugPrint("Client packet number map updated")

}

func translateAckPacketNumber(pn int64, conn packet_setting.QuicConnection) (int64, error) {

	qconn := conn.(quic.Connection)

	if qconn.RemoteAddr().String() == server_addr {
		// fmt.Println("Not translating pn for server")
		return pn, nil
	}
	debugPrint("TRANSLATE", pn)
	debugPrint("Translated packet number", qconn.RemoteAddr().String())

	ipaddr, port := getIPAndPort(qconn)
	client_key := client_key_struct{
		Ipaddr:  swapEndianness32(ipToInt32(ipaddr)),
		Port:    swapEndianness16(uint16(port)),
		Padding: [2]uint8{0, 0},
	}
	key := client_pn_map_key{
		Key: client_key,
		Pn:  uint32(pn),
	}

	client_pn_translator, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/connection_pn_translation", &ebpf.LoadPinOptions{})
	if err != nil {
		fmt.Println("Error loading client_pn_translator")
		panic(err)
	}
	val := &connnection_pn_stuct{}
	err = client_pn_translator.Lookup(key, val)
	if err != nil {
		debugPrint("No entry for ", pn)

		// for smaller_pn := pn; smaller_pn > 0; smaller_pn-- {
		// 	key.Pn = uint32(smaller_pn)
		// 	err = client_pn_translator.Lookup(key, val)
		// 	if err == nil {
		// 		return int64(val.Pn), nil
		// 	}
		// }
		debugPrint("Error looking up in client_pn_translator")
		return pn, nil
	}

	debugPrint(pn, "->", val.Pn)

	translated_pn := int64(val.Pn)
	debugPrint(translated_pn)
	return translated_pn, nil
}

// TODO this is probably not the most elegant way to clear the BPF maps
func clearBPFMaps() {

	paths := []string{
		"client_data",
		"client_id",
		"id_counter",
		"number_of_clients",
		"connection_established",
		"client_pn",
		"connection_current_pn",
		"connection_pn_translation",
		"connection_unistream_id_counter",
		"connection_unistream_id_translation",
		"client_stream_offset",
		"packets_to_register",
		"index_packets_to_register"}
	map_location := "/sys/fs/bpf/tc/globals/"

	for _, path := range paths {
		cmd := exec.Command("../../../utils/build/clear_bpf_map", map_location+path)
		stdout, err := cmd.Output()
		if err != nil {
			fmt.Println(string(stdout))
			panic(err)
		}
		fmt.Println(string(stdout))
	}
}
