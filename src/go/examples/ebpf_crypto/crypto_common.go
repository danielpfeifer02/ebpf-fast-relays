package main

import (
	"fmt"
	"os"

	"common.com/common"
	"github.com/cilium/ebpf"
	crypto_settings "golang.org/x/crypto"

	mapset "github.com/deckarep/golang-set/v2"
)

const writeToFile = false

var tls_chacha20_poly1305_bitstream_server *ebpf.Map = nil
var last_decrypted_pn *ebpf.Map = nil

var fully_received_packets mapset.Set[uint64] = mapset.NewSet[uint64]()

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
	go func() {
		key := tls_chacha20_poly1305_bitstream_access_key{PacketNumber: pn, BlockIndex: blockindex, Padding: [7]uint8{0, 0, 0, 0, 0, 0, 0}}
		err := tls_chacha20_poly1305_bitstream_server.Put(key, bitstream) // TODO: sizing should always be 64 byte so no worries here?
		if err != nil {
			panic(err)
		}
	}()
}

func potentiallTriggerCryptoGarbageCollector() {

	// This garbage collector works by checking the last decrypted packet number and removing all bitstreams
	// regarding earlier packets numbers. This prevents memory leaks in the eBPF map.

	// Get last decrypted packet number
	var last_decrypted_pn_value uint64
	err := last_decrypted_pn.Lookup(uint32(0), &last_decrypted_pn_value)
	if err != nil {
		panic(err)
	}

	// Pop one item at a time until empty and handle if if ok
	for {
		pn, ok := fully_received_packets.Pop()
		if !ok {
			break
		}

		deleteAllBlocksOfPNBitstream(pn)

		// TODO: remove: the last_decrypted_pn_value is always larger than the packet number if the packet was fully received

		// // If the packet number is smaller than the last decrypted packet number, remove the bitstream
		// if pn < last_decrypted_pn_value {
		// 	// Remove bitstream
		// 	deleteAllBlocksOfPNBitstream(pn)
		// }
	}
}

func deleteAllBlocksOfPNBitstream(pn uint64) {
	for b_id := 0; b_id < crypto_settings.MAX_BLOCKS_PER_PACKET; b_id++ {
		err := tls_chacha20_poly1305_bitstream_server.Delete(tls_chacha20_poly1305_bitstream_access_key{PacketNumber: pn, BlockIndex: uint8(b_id), Padding: [7]uint8{0, 0, 0, 0, 0, 0, 0}})
		if err == ebpf.ErrKeyNotExist {
			continue // If the key does not exist we do not care since that only means the ebpf program itself already cleaned up that block
		}
		if err != nil {
			panic(err)
		}
	}
}
func registerFullyReceivedPacket(pn uint64) {
	fully_received_packets.Add(pn)
}

func loadEBPFCryptoMaps() {
	tls_chacha20_poly1305_bitstream_server = common.LoadMap("/sys/fs/bpf/tc/globals/tls_chacha20_poly1305_bitstream_server")
	last_decrypted_pn = common.LoadMap("/sys/fs/bpf/tc/globals/last_decrypted_pn")
}
