package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"common.com/common"
	"github.com/cilium/ebpf"
	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
)

// map [6 bytes] -> [map[uint64] -> uint64]
var sent_storage map[[6]byte]map[uint64]uint64

var sent_storage_lock = sync.Mutex{}

func setupOOBConnectionRelaySide() {

	if !bpf_enabled {
		fmt.Println("BPF not enabled, not setting up out of band connection since it does not make sense")
		return
	}

	ctx := context.Background()
	tlsConfig := generateTLSConfig(false)
	listener, err := quic.ListenAddr(oob_addr_server, tlsConfig, generateQUICConfig())
	if err != nil {
		panic(err)
	}
	conn, err := listener.Accept(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("Accepted out of band connection")
	oob_conn = conn

	if sent_storage == nil {
		sent_storage = make(map[[6]byte]map[uint64]uint64)
	}

	go ReadPnTsSent()

	startOOBHandler()
}

func setupOOBConnectionClientSide() {

	if !bpf_enabled {
		fmt.Println("BPF not enabled, not setting up out of band connection since it does not make sense")
		return
	}

	ctx := context.Background()
	tlsConfig := generateTLSConfig(false)
	conn, err := quic.DialAddr(ctx, oob_addr_server, tlsConfig, generateQUICConfig())
	if err != nil {
		panic(err)
	}
	oob_conn = conn
	fmt.Println("Connected to out of band connection")
}

func startOOBHandler() {
	if oob_conn == nil {
		panic("oob_conn is nil but handler was started")
	}

	indices := register_client(default_ewma_alpha, default_max_hist_size)
	go func() {
		for {
			buf, err := oob_conn.ReceiveDatagram(context.Background())
			if err != nil {
				panic(err)
			}
			pn := binary.LittleEndian.Uint64(buf[:8])
			ts := binary.LittleEndian.Uint64(buf[8:])
			ip := binary.LittleEndian.Uint32(buf[16:])
			port := binary.LittleEndian.Uint16(buf[20:])
			netip := net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
			handlePnTsRecv(pn, ts, netip, port, indices)
		}
	}()
}

func StartTimestampHandler(recv_chan chan common.Timestamp_struct) {

	aggregation_list := make([]common.Timestamp_struct, ts_aggregation_window)
	aggregation_index := 0
	for {
		ts_aggregate := <-recv_chan
		if aggregation_index == ts_aggregation_window {
			aggregation_index = 0

			// Open log file
			file, err := os.OpenFile(packet_timestamp_file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				panic(err)
			}

			for _, val := range aggregation_list {
				_, err = file.WriteString(fmt.Sprintf("%d %d\n", val.PacketNumber, val.Timestamp))
				if err != nil {
					panic(err)
				}
			}

			// Close log file
			err = file.Close()
			if err != nil {
				panic(err)
			}
		}
		aggregation_list[aggregation_index] = ts_aggregate
		aggregation_index++
	}
}

func receivedPacketAtTimestamp(pn, ts int64, conn packet_setting.QuicConnection) {

	if log_packet_timestamps {

		// Send to log channel
		packet_timestamp_chan <- common.Timestamp_struct{
			PacketNumber: pn,
			Timestamp:    ts,
		}

	}

	if oob_data_transmission && oob_conn != nil {
		buf := make([]byte, 22) // 8 bytes for pn, 8 bytes for ts, 4 bytes for IP, 2 bytes for port
		binary.LittleEndian.PutUint64(buf, uint64(pn))
		binary.LittleEndian.PutUint64(buf[8:], uint64(ts))

		// if conn.RemoteAddr().String() == relay_server_address {
		// 	fmt.Println("Received packet with pn", pn, "at timestamp", ts)
		// }

		qconn := conn.(quic.Connection)
		ipaddr, port := common.GetIPAndPort(qconn, true)
		ipv4 := ipaddr.To4()
		if ipv4 == nil {
			panic("Invalid IP address (non-IPv4)")
		}

		if port != 4242 {
			return
		}

		// fmt.Println("Local:", qconn.LocalAddr().String(), "\nRemote:", qconn.RemoteAddr().String())

		// TODO: This still poses a problem since the quic connection has the zero address
		// TODO: as "LocalAddr" which means any address is ok. But we need to know the local
		// TODO: address so that the relay can have a correct key for looking up.
		// TODO: Figure out how to solve this.
		tmp, _ := strconv.Atoi(strings.Split(qconn.LocalAddr().String(), ":")[3])
		port = uint16(tmp)
		ipv4 = net.IPv4(192, 168, 11, 1) // TODO: For now just hardcode the IP address of the example

		binary.LittleEndian.PutUint32(buf[16:], common.IpToInt32(ipv4))
		binary.LittleEndian.PutUint16(buf[20:], port)

		oob_conn.SendDatagram(buf)
	}
}

func handlePnTsRecv(pn, ts uint64, ip net.IP, port uint16, indices client_indices) {

	// fmt.Println("Receive pn:", pn, ", ts:", ts, ", ip:", ip, ", port:", port)

	key := [6]byte{ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port & 0xFF)}
	sent_storage_lock.Lock()
	defer sent_storage_lock.Unlock()
	if conn_storage, ok := sent_storage[key]; ok {
		// sent_storage_lock.Unlock()
		if sent_ts, ok := conn_storage[pn]; ok { // TODO: delete the entry from the map
			packet_info := common.Pn_ts_struct{
				PacketNumber: uint32(pn),
				IpAddr:       common.IpToInt32(ip),
				Timestamp:    ts,
				Port:         port,
				Valid:        1,
			}
			ca_ts_handler(sent_ts, ts, packet_info, indices)
		}
	}
	// sent_storage_lock.Unlock()

}

func ReadPnTsSent() {

	index_pn_ts_storage := 0

	for {

		pn_ts := &common.Pn_ts_struct{}
		err := common.Pn_ts_storage.Lookup(uint32(index_pn_ts_storage), pn_ts)
		if err == nil && pn_ts.Valid == 1 {
			netIP := net.IPv4(byte(pn_ts.IpAddr), byte(pn_ts.IpAddr>>8), byte(pn_ts.IpAddr>>16), byte(pn_ts.IpAddr>>24))
			netPort := ((pn_ts.Port & 0xff) << 8) | ((pn_ts.Port & 0xff00) >> 8)
			StorePnTsSent(uint64(pn_ts.PacketNumber), pn_ts.Timestamp, netIP, netPort)

			pn_ts.Valid = 0
			err = common.Pn_ts_storage.Update(uint32(index_pn_ts_storage), pn_ts, ebpf.UpdateAny)
			if err != nil {
				fmt.Println("Error updating pn_ts_storage")
				panic(err)
			}

			index_pn_ts_storage++
			if index_pn_ts_storage == 2048 { // TODO: save as const once final size is known
				index_pn_ts_storage = 0
			}
		} else {
			// fmt.Println(err)
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func StorePnTsSent(pn, ts uint64, ip net.IP, port uint16) {

	// fmt.Println("Store pn:", pn, ", ts:", ts, ", ip:", ip, ", port:", port)

	key := [6]byte{ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port & 0xFF)}

	sent_storage_lock.Lock()
	defer sent_storage_lock.Unlock()
	if sent_storage[key] == nil {
		sent_storage[key] = make(map[uint64]uint64)
	}
	sent_storage[key][pn] = ts
	// sent_storage_lock.Unlock()
}
