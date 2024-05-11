package main

import "github.com/danielpfeifer02/quic-go-prio-packs"

type pn_struct struct {
	Pn      uint16
	Changed uint8
	Padding [3]uint8
}

type connnection_pn_stuct struct {
	Pn uint32
}

type id_struct struct {
	Id uint32
}

type client_key_struct struct {
	Ipaddr  uint32
	Port    uint16
	Padding [2]uint8
}

type client_pn_map_key struct {
	Key client_key_struct
	Pn  uint32
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

type client_connection struct {
	conn   quic.Connection
	stream quic.Stream
}
