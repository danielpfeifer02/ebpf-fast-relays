package common

type connnection_pn_stuct struct {
	Pn uint32
}

type id_struct struct {
	Id uint32
}

type established_val_struct struct {
	Established uint8
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
	Offset       uint64

	ServerPN uint32 // TODO: rename into OldPacketNumber since its not necessarily the server's packet number

	Valid           uint8
	ForwardedPacket uint8
	Padding         [2]uint8
}

type index_key_struct struct {
	Index uint32
}

type sender_spec_struct struct {
	FilePath        string
	KeyFrameMaxDist uint32
	KeyFrameMinDist uint32
}

type pn_ts_struct struct {
	PacketNumber uint32
	IpAddr       uint32
	Timestamp    uint64
	Port         uint16
	Valid        uint8
	Padding      [5]uint8
}

type packet_is_retransmission_struct struct {
	StreamID     uint64
	PacketNumber uint32
	ConnectionID [16]uint8
	Padding      [4]uint8
}

type unistream_id_retransmission_struct struct {
	IpAddr   uint32
	Port     uint16
	Padding  [2]uint8
	StreamId uint64
}

type retransmission_val_struct struct {
	IsRetransmission uint8
}
