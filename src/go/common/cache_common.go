package common

import (
	"sync"

	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
)

var storage_server_packets map[int64]packet_setting.RetransmissionPacketContainer
var lock *sync.Mutex

func InitializeCacheSetup() {
	storage_server_packets = make(map[int64]packet_setting.RetransmissionPacketContainer)
	lock = &sync.Mutex{}
}

func StoreServerPacket(pn, ts int64, data []byte,
	conn packet_setting.QuicConnection) {
	lock.Lock()
	defer lock.Unlock()
	storage_server_packets[pn] = packet_setting.RetransmissionPacketContainer{
		PacketNumber: pn,
		Length:       int64(len(data)),
		Timestamp:    ts,
		RawData:      data,
		Valid:        true,
	}
}

func RemoveServerPacket(pn int64, conn packet_setting.QuicConnection) {
	delete(storage_server_packets, pn)
}

func RetreiveServerPacket(pn int64) packet_setting.RetransmissionPacketContainer {
	if pn == 4294967295 { // TODO: don't use max uint32
		return packet_setting.RetransmissionPacketContainer{
			Valid: false,
		}
	}
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

func GetRetransmitServerPacketAfterPNTranslation(bpf_pn int64, conn packet_setting.QuicConnection) packet_setting.RetransmissionPacketContainer {
	return packet_setting.RetransmissionPacketContainer{
		Valid: false,
	}
}
