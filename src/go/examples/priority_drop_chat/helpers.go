package main

import (
	"fmt"
	"net"

	"common.com/common"
	"github.com/danielpfeifer02/quic-go-prio-packs"
)

func getConnectionIDsKey(qconn quic.Connection) [6]byte {
	return common.GetConnectionIDsKey(qconn)
}

func getIPAndPort(conn quic.Connection) (net.IP, uint16) {
	return common.GetIPAndPort(conn, true)
}

func IpToInt32(ip net.IP) uint32 {
	return common.IpToInt32(ip)
}

func swapEndianness16(val uint16) uint16 {
	return common.SwapEndianness16(val)
}

func swapEndianness32(val uint32) uint32 {
	return common.SwapEndianness32(val)
}

func debugPrint(p ...interface{}) {
	if DEBUG_PRINT {
		fmt.Println(p...)
	}
}
