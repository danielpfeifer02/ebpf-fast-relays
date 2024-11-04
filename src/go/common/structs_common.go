package common

type Connnection_pn_stuct struct {
	Pn uint32
}

type Id_struct struct {
	Id uint32
}

type Established_val_struct struct {
	Established uint8
}

type Client_key_struct struct {
	Ipaddr  uint32
	Port    uint16
	Padding [2]uint8
}

type Client_pn_map_key struct {
	Key Client_key_struct
	Pn  uint32
}

type Client_data_struct struct {
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

type Packet_register_struct struct {
	PacketNumber uint64
	SentTime     uint64
	Length       uint64
	Offset       uint64

	ServerPN uint32 // TODO: rename into OldPacketNumber since its not necessarily the server's packet number

	Flags uint32
}

type Index_key_struct struct {
	Index uint32
}

type Sender_spec_struct struct {
	FilePath        string
	KeyFrameMaxDist uint32
	KeyFrameMinDist uint32
}

type Pn_ts_struct struct {
	PacketNumber uint32
	IpAddr       uint32
	Timestamp    uint64
	Port         uint16
	Valid        uint8
	Padding      [5]uint8
}

type Packet_is_retransmission_struct struct {
	StreamID     uint64
	PacketNumber uint32
	ConnectionID [16]uint8
	Padding      [4]uint8
}

type Unistream_id_retransmission_struct struct {
	IpAddr   uint32
	Port     uint16
	Padding  [2]uint8
	StreamId uint64
}

type Retransmission_val_struct struct {
	IsRetransmission uint8
}
