package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/go-gst/go-gst/gst"
)

func getConnectionIDsKey(qconn quic.Connection) [6]byte {
	ipaddr, port := getIPAndPort(qconn)
	ipv4 := ipaddr.To4()
	if ipv4 == nil {
		panic("Invalid IP address")
	}
	return [6]byte{ipv4[0], ipv4[1], ipv4[2], ipv4[3], byte(port >> 8), byte(port & 0xFF)}
}

func getIPAndPort(conn quic.Connection) (net.IP, uint16) {
	tup := strings.Split(conn.RemoteAddr().String(), ":")
	ipaddr := net.ParseIP(tup[0])
	if ipaddr == nil {
		panic("Invalid IP address")
	}
	port, err := strconv.Atoi(tup[1])
	if err != nil {
		panic(err)
	}
	return ipaddr, uint16(port)
}

func ipToInt32(ip net.IP) uint32 {
	// Convert to IPv4
	ip = ip.To4()
	if ip == nil {
		panic("Trying to convert an invalid IPv4 address")
	}
	// Convert IPv4 address to integer
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func swapEndianness16(val uint16) uint16 {
	return (val&0xFF)<<8 | (val&0xFF00)>>8
}

func swapEndianness32(val uint32) uint32 {
	return (val&0xFF)<<24 | (val&0xFF00)<<8 | (val&0xFF0000)>>8 | (val&0xFF000000)>>24
}

func debugPrint(p ...interface{}) {
	if DEBUG_PRINT {
		fmt.Println(p...)
	}
}

func getElementByName(pipeline *gst.Pipeline, name string) *gst.Element {
	elements, err := pipeline.GetElements()
	if err != nil {
		panic(err)
	}
	for _, element := range elements {
		if element.GetName() == name {
			return element
		}
	}
	return nil
}
