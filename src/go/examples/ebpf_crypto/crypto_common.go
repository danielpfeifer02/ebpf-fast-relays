package main

import (
	"fmt"
	"os"

	"common.com/common"
	"github.com/cilium/ebpf"
)

const writeToFile = false

var tls_chacha20_poly1305_bitstream_server *ebpf.Map = nil

type tls_chacha20_poly1305_bitstream_access_key struct {
	PacketNumber uint64
	BlockIndex   uint8
	Padding      [7]uint8
}

func eBPFXOrBitstreamRegister(pn uint64, blockindex uint8, bitstream []byte) {

	if writeToFile {
		tmpfilepath := fmt.Sprintf("/tmp/ebpf_crypto_%d", pn)

		// Open file truncating it
		file, err := os.OpenFile(tmpfilepath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			fmt.Println("Error opening file", err)
			return
		}

		// Write bitstream to file
		for i := 0; i < len(bitstream); i++ {
			str := fmt.Sprintf("%02x", bitstream[i])
			_, err = file.WriteString(str)
		}
		if err != nil {
			fmt.Println("Error writing to file", err)
			return
		}
	}

	// Write bitstream to map
	key := tls_chacha20_poly1305_bitstream_access_key{PacketNumber: pn, BlockIndex: blockindex, Padding: [7]uint8{0, 0, 0, 0, 0, 0, 0}}
	err := tls_chacha20_poly1305_bitstream_server.Put(key, bitstream) // TODO: sizing should always be 64 byte so no worries here?
	if err != nil {
		panic(err)
	}
}

func loadEBPFCryptoMaps() {
	tls_chacha20_poly1305_bitstream_server = common.LoadMap("/sys/fs/bpf/tc/globals/tls_chacha20_poly1305_bitstream_server")
}
