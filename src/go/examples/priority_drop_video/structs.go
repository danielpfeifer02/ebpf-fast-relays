package main

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

type packet_register_struct struct {
	PacketNumber uint64
	SentTime     uint64
	Length       uint64
	Valid        uint8
	Padding      [7]uint8
}

type index_key_struct struct {
	Index uint32
}
