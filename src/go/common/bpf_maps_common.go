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
var Client_stream_offset *ebpf.Map = nil
var Packets_to_register *ebpf.Map = nil
var Index_packets_to_register *ebpf.Map = nil
var Pn_ts_storage *ebpf.Map = nil
var Index_pn_ts_storage *ebpf.Map = nil

func LoadBPFMaps() {
	base_dir := "/sys/fs/bpf/tc/globals/"

	Id_counter = loadMap(base_dir + "id_counter")
	Client_data = loadMap(base_dir + "client_data")
	Number_of_clients = loadMap(base_dir + "number_of_clients")
	Client_id = loadMap(base_dir + "client_id")
	Connection_established = loadMap(base_dir + "connection_established")
	Client_pn = loadMap(base_dir + "client_pn")
	Connection_current_pn = loadMap(base_dir + "connection_current_pn")
	Connection_pn_translation = loadMap(base_dir + "connection_pn_translation")
	Client_stream_offset = loadMap(base_dir + "client_stream_offset")
	Packets_to_register = loadMap(base_dir + "packets_to_register")
	Index_packets_to_register = loadMap(base_dir + "index_packets_to_register")
	Pn_ts_storage = loadMap(base_dir + "pn_ts_storage")
	Index_pn_ts_storage = loadMap(base_dir + "index_pn_ts_storage")
}

func loadMap(path string) *ebpf.Map {
	m, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{})
	if err != nil {
		panic("Failed to load map: " + path + "(" + err.Error() + ")")
	} else {
		fmt.Println("Loaded map", path)
	}
	return m
}
