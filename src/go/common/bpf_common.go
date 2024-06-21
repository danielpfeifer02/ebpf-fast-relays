package common

// TODO: add everything here that is used for the video example as well as for the performance analysis

// TODO: change all calls from the examples from bpf_handler.go to here

import (
	"fmt"
	"net"
	"os/exec"
	"time"

	"github.com/cilium/ebpf"
	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
)

// This function will clear all BPF maps once the relay is started.
// This relies on an external C program since there exist wrappers
// to iterate over keys of a map.
// Ideally this would also be done in Go.
// TODO: not the most elegant way to clear the BPF maps
func ClearBPFMaps() {

	paths := []string{
		"client_data",
		"client_id",
		"id_counter",
		"number_of_clients",
		"client_pn",
		"connection_current_pn",
		"connection_pn_translation",
		"client_stream_offset"}
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

// This function is used for registering the packets that have been sent by the
// BPF program.
func RegisterBPFPacket(conn quic.Connection) {

	go func() {

		ipaddr, port := GetIPAndPort(conn, true)
		key := client_key_struct{
			Ipaddr:  swapEndianness32(ipToInt32(ipaddr)),
			Port:    swapEndianness16(port),
			Padding: [2]uint8{0, 0},
		}

		current_pn := &connnection_pn_stuct{}
		for {

			err := connection_current_pn.Lookup(key, current_pn)
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

	for {

		// Check if there are packets to register
		err := packets_to_register.Lookup(current_index, val)
		if err == nil && val.Valid == 1 { // TODO: why not valid?

			// fmt.Println("Register packet number", val.PacketNumber, "at index", current_index.Index, "at time", time.Now().UnixNano())

			go func(val packet_register_struct, idx index_key_struct, mp *ebpf.Map) { // TODO: speed up when using goroutines?

				var server_pack packet_setting.RetransmissionPacketContainer
				for {
					server_pack = RetreiveServerPacket(int64(val.ServerPN))
					if server_pack.Valid {
						break
					}
					time.Sleep(1 * time.Millisecond) // TODO: optimal?
				}
				if len(server_pack.RawData) == 0 {
					panic("No server packet found")
				}

				// if server_pack.Length != int64(val.Length) { // TODO: useful check?
				// 	fmt.Println(server_pack.Length, val.Length)
				// 	panic("Lengths do not match")
				// }

				packet := packet_setting.PacketRegisterContainerBPF{
					PacketNumber: int64(val.PacketNumber),
					SentTime:     int64(val.SentTime),
					Length:       int64(val.Length), // TODO: length needed if its in server_pack?

					RawData: server_pack.RawData,

					// These two will be set in the wrapper of the quic connection.
					Frames:       nil,
					StreamFrames: nil,
				}

				conn.RegisterBPFPacket(packet)

				// Set valid to 0 to indicate that the packet has been registered
				val.Valid = 0
				err = mp.Update(idx, val, ebpf.UpdateAny)
				if err != nil {
					fmt.Println("Error updating buffer map")
					panic(err)
				}

			}(*val, current_index, packets_to_register) // this pass by copy is necessary since the goroutine might be executed after the next iteration

			current_index.Index = uint32((current_index.Index + 1) % uint32(max_register_queue_size))
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

	err := connection_established.Update(key, est, ebpf.UpdateAny)
	if err != nil {
		fmt.Println("Error updating established", err)
		return err
	}

	fmt.Println("Connection established for", ip, ":", port)
	return nil
}
