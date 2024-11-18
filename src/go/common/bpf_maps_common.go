package common

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// TODO: how to handle if already loaded?

var Id_counter *ebpf.Map = nil
var Client_data *ebpf.Map = nil
var Number_of_clients *ebpf.Map = nil
var Client_id *ebpf.Map = nil
var Connection_established *ebpf.Map = nil
var Client_pn *ebpf.Map = nil
var Connection_current_pn *ebpf.Map = nil
var Connection_pn_translation *ebpf.Map = nil
var Connection_unistream_id_counter *ebpf.Map = nil
var Connection_unistream_id_translation *ebpf.Map = nil
var Client_stream_offset *ebpf.Map = nil
var Packets_to_register *ebpf.Map = nil
var Index_packets_to_register *ebpf.Map = nil
var Pn_ts_storage *ebpf.Map = nil
var Index_pn_ts_storage *ebpf.Map = nil
var Unistream_id_is_retransmission *ebpf.Map = nil
var Packet_is_retransmission *ebpf.Map = nil

func LoadBPFMaps() {
	base_dir := "/sys/fs/bpf/tc/globals/"

	Id_counter = LoadMap(base_dir + "id_counter")
	Client_data = LoadMap(base_dir + "client_data")
	Number_of_clients = LoadMap(base_dir + "number_of_clients")
	Client_id = LoadMap(base_dir + "client_id")
	Connection_established = LoadMap(base_dir + "connection_established")
	Client_pn = LoadMap(base_dir + "client_pn")
	Connection_current_pn = LoadMap(base_dir + "connection_current_pn")
	Connection_pn_translation = LoadMap(base_dir + "connection_pn_translation")
	Connection_unistream_id_counter = LoadMap(base_dir + "connection_unistream_id_counter")
	Connection_unistream_id_translation = LoadMap(base_dir + "connection_unistream_id_translation")
	Client_stream_offset = LoadMap(base_dir + "client_stream_offset")
	Packets_to_register = LoadMap(base_dir + "packets_to_register")
	Index_packets_to_register = LoadMap(base_dir + "index_packets_to_register")
	Pn_ts_storage = LoadMap(base_dir + "pn_ts_storage")
	Index_pn_ts_storage = LoadMap(base_dir + "index_pn_ts_storage")
	Unistream_id_is_retransmission = LoadMap(base_dir + "unistream_id_is_retransmission")
	Packet_is_retransmission = LoadMap(base_dir + "packet_is_retransmission")
}

func LoadMap(path string) *ebpf.Map {
	m, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{})
	if err != nil {
		panic("Failed to load map: " + path + "(" + err.Error() + ")")
	} else {
		fmt.Println("Loaded map", path)
	}
	return m
}
