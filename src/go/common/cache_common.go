package common

import (
	"fmt"
	"sync"

	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
)

var storage_server_packets map[int64]packet_setting.RetransmissionPacketContainer
var lock *sync.Mutex

var debug_length = 20
var debug_packet_storage = false

var storage_relay_packets map[int64]packet_setting.RetransmissionPacketContainer
var lock_relay *sync.Mutex

func InitializeCacheSetup() {
	storage_server_packets = make(map[int64]packet_setting.RetransmissionPacketContainer)
	lock = &sync.Mutex{}

	storage_relay_packets = make(map[int64]packet_setting.RetransmissionPacketContainer)
	lock_relay = &sync.Mutex{}
}

func StoreServerPacket(pn, ts int64, data []byte,
	conn packet_setting.QuicConnection) {

	lock.Lock()
	defer lock.Unlock()

	storage_server_packets[pn] = packet_setting.RetransmissionPacketContainer{
		PacketNumber: pn,
		Length:       int64(len(data)),
		Timestamp:    ts, // TODO: correct timestamp?
		RawData:      data,
		Valid:        true,
	}

	if debug_packet_storage {
		fmt.Print("Storing (from common) server packet for pn ", pn, " and data:")
		for i := 0; i < min(len(data), debug_length); i++ {
			fmt.Printf(" %x", data[i])
		}
		fmt.Println()
	}
}

func StoreRelayPacket(pn, ts int64, data []byte,
	conn packet_setting.QuicConnection) {
	lock_relay.Lock()
	defer lock_relay.Unlock()
	storage_relay_packets[pn] = packet_setting.RetransmissionPacketContainer{
		PacketNumber: pn,
		Length:       int64(len(data)),
		Timestamp:    ts, // TODO: correct timestamp?
		RawData:      data,
		Valid:        true,
	}

	if debug_packet_storage {
		fmt.Print("Storing (from common) relay packet for pn ", pn, " and data:")
		for i := 0; i < min(len(data), debug_length); i++ {
			fmt.Printf(" %x", data[i])
		}
		fmt.Println()
	}
}

func PacketOriginatedAtRelay(pn int64) bool {
	for k := range storage_relay_packets {
		if k == pn {
			return true
		}
	}
	return false
}

func RemoveServerPacket(pn int64, conn packet_setting.QuicConnection) {
	delete(storage_server_packets, pn)
}

func RemoveRelayPacket(pn int64, conn packet_setting.QuicConnection) {
	delete(storage_relay_packets, pn)
}

func RetreiveServerPacket(pn int64) packet_setting.RetransmissionPacketContainer {
	if pn == 4294967295 { // TODO: don't use max uint32
		return packet_setting.RetransmissionPacketContainer{
			Valid: false,
		}
	}
	// fmt.Println("Retrieving (from common) server packet for pn", pn)
	lock.Lock()
	defer lock.Unlock()
	if _, ok := storage_server_packets[pn]; ok {
		return storage_server_packets[pn]
	}
	return packet_setting.RetransmissionPacketContainer{
		Valid: false,
	}
	// panic(fmt.Sprintf("Packet (%d) not found", pn)) // TODO: why is this happening?
}

func RetreiveRelayPacket(pn int64) packet_setting.RetransmissionPacketContainer {
	if pn == 4294967295 { // TODO: don't use max uint32
		return packet_setting.RetransmissionPacketContainer{
			Valid: false,
		}
	}
	lock_relay.Lock()
	defer lock_relay.Unlock()
	if _, ok := storage_relay_packets[pn]; ok {
		return storage_relay_packets[pn]
	}
	return packet_setting.RetransmissionPacketContainer{
		Valid: false,
	}
	// panic(fmt.Sprintf("Packet (%d) not found (relay)", pn)) // TODO: is this happening?
}

func GetRetransmitServerPacketAfterPNTranslation(bpf_pn int64, conn packet_setting.QuicConnection) packet_setting.RetransmissionPacketContainer {
	return packet_setting.RetransmissionPacketContainer{
		Valid: false,
	}
}
