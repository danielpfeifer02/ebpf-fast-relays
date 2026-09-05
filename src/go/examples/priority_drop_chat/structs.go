package main

import (
	"common.com/common"
	"github.com/danielpfeifer02/quic-go-prio-packs"
)

// Legacy alias kept for an older map layout used only in this example.
type pn_struct struct {
	Pn      uint16
	Changed uint8
	Padding [3]uint8
}

// Aliases to shared BPF map structs (moved into common).
type connnection_pn_stuct = common.Connnection_pn_stuct
type id_struct = common.Id_struct
type conn_established_struct = common.Established_val_struct
type client_key_struct = common.Client_key_struct
type client_pn_map_key = common.Client_pn_map_key
type client_data_struct = common.Client_data_struct

type StreamingStream struct {
	stream     quic.Stream
	connection quic.Connection
}

type client_connection struct {
	conn   quic.Connection
	stream quic.Stream
}
