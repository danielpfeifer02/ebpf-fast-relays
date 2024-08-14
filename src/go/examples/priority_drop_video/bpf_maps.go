package main

import (
	"fmt"

	"github.com/cilium/ebpf"
)

var id_counter *ebpf.Map = nil
var client_data *ebpf.Map = nil
var number_of_clients *ebpf.Map = nil
var client_id *ebpf.Map = nil
var connection_established *ebpf.Map = nil
var client_pn *ebpf.Map = nil
var connection_current_pn *ebpf.Map = nil
var connection_pn_translation *ebpf.Map = nil
var connection_unistream_id_counter *ebpf.Map = nil
var connection_unistream_id_translation *ebpf.Map = nil
var client_stream_offset *ebpf.Map = nil
var packets_to_register *ebpf.Map = nil
var index_packets_to_register *ebpf.Map = nil
var pn_ts_storage *ebpf.Map = nil
var index_pn_ts_storage *ebpf.Map = nil
var unistream_id_is_retransmission *ebpf.Map = nil

func loadBPFMaps() {
	base_dir := "/sys/fs/bpf/tc/globals/"

	id_counter = loadMap(base_dir + "id_counter")
	client_data = loadMap(base_dir + "client_data")
	number_of_clients = loadMap(base_dir + "number_of_clients")
	client_id = loadMap(base_dir + "client_id")
	connection_established = loadMap(base_dir + "connection_established")
	client_pn = loadMap(base_dir + "client_pn")
	connection_current_pn = loadMap(base_dir + "connection_current_pn")
	connection_pn_translation = loadMap(base_dir + "connection_pn_translation")
	connection_unistream_id_counter = loadMap(base_dir + "connection_unistream_id_counter")
	connection_unistream_id_translation = loadMap(base_dir + "connection_unistream_id_translation")
	client_stream_offset = loadMap(base_dir + "client_stream_offset")
	packets_to_register = loadMap(base_dir + "packets_to_register")
	index_packets_to_register = loadMap(base_dir + "index_packets_to_register")
	pn_ts_storage = loadMap(base_dir + "pn_ts_storage")
	index_pn_ts_storage = loadMap(base_dir + "index_pn_ts_storage")
	unistream_id_is_retransmission = loadMap(base_dir + "unistream_id_is_retransmission")
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
