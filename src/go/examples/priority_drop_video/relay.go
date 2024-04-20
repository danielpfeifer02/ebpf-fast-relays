package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf"
	moqtransport "github.com/danielpfeifer02/priority-moqtransport"
)

func relay() error {

	var number_of_clients *ebpf.Map
	var err error
	if bpf_enabled {
		clearBPFMaps()
		number_of_clients, err = ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/number_of_clients", &ebpf.LoadPinOptions{})
		if err != nil {
			panic(err)
		}
		client_ctr := uint32(0)
		err = number_of_clients.Update(uint32(0), client_ctr, 0)
		if err != nil {
			panic(err)
		}
	}

	announcementCh := make(chan string)

	c, err := moqtransport.DialQUIC(context.Background(), video_server_address)
	if err != nil {
		panic(err)
	}

	fmt.Println("moq peer connected")
	c.OnAnnouncement(func(s string) error {
		log.Printf("handling announcement of track %v", s)
		announcementCh <- s
		return nil
	})

	fmt.Println("waiting for announcement")
	trackname := <-announcementCh
	t, err := c.Subscribe(trackname)
	if err != nil {
		panic(err)
	}

	sendTrackList := make([]moqtransport.SendTrack, 0)

	go func(t *moqtransport.ReceiveTrack) {
		for {
			buf := make([]byte, 64_000)
			n, err := t.Read(buf)
			if err != nil {
				log.Printf("error on read: %v", err)
				return
			}

			if relay_passing_on {
				for _, st := range sendTrackList {
					_, err := st.Write(buf[:n])
					if err != nil {
						log.Printf("error on write: %v", err)
						return
					}
				}
			}
		}
	}(t)

	s := moqtransport.Server{
		Handler: moqtransport.PeerHandlerFunc(func(p *moqtransport.Peer) {
			fmt.Println("handling new peer")
			defer log.Println("XXX")
			p.OnAnnouncement(func(s string) error {
				log.Printf("got announcement: %v", s)
				return nil
			})
			if err := p.Announce("video"); err != nil {
				log.Printf("failed to announce video: %v", err)
			}
			fmt.Println("announced video namespace")
			p.OnSubscription(func(s string, st *moqtransport.SendTrack) (uint64, time.Duration, error) {
				log.Printf("handling subscription to track %s", s)
				if s != "video" {
					return 0, 0, errors.New("unknown trackname")
				}

				// update number of clients
				if bpf_enabled {
					client_ctr := uint32(0)
					err = number_of_clients.Lookup(uint32(0), &client_ctr)
					if err != nil {
						panic(err)
					}
					client_ctr++
					err = number_of_clients.Update(uint32(0), client_ctr, 0)
					if err != nil {
						panic(err)
					}
					fmt.Println("updated number of clients")

					// publish connection established (TODO: correct place for that?)
					testPublishConnEstablished()
				}

				sendTrackList = append(sendTrackList, *st)
				fmt.Println("added track to sendTrackList")

				return 0, 0, nil
			})
		}),
		TLSConfig: video_generateTLSConfig(true),
	}
	if err := s.ListenQUIC(context.Background(), relay_server_address); err != nil {
		panic(err)
	}
	return nil

}

// TODO: make better so that this also works for multiple clients
func testPublishConnEstablished() {
	time.Sleep(1 * time.Second)
	if bpf_enabled {
		connection_map, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/connection_established", &ebpf.LoadPinOptions{})
		if err != nil {
			panic(err)
		}

		ipaddr := net.IPv4(192, 168, 11, 1)
		port := uint16(4242)
		ipaddr_key := swapEndianness32(ipToInt32(ipaddr))
		port_key := swapEndianness16(port)

		key := client_key_struct{
			Ipaddr:  ipaddr_key,
			Port:    port_key,
			Padding: [2]uint8{0, 0},
		}
		estab := &conn_established_struct{
			Established: uint8(1),
		}
		err = connection_map.Update(key, estab, 0)
		debugPrint("Update at point nr.", 10)
		if err != nil {
			panic(err)
		}
		fmt.Println("R: Connection established")
	}
}
