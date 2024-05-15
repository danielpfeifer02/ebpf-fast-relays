package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	moqtransport "github.com/danielpfeifer02/priority-moqtransport"
	"github.com/danielpfeifer02/priority-moqtransport/quicmoq"
	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/mengelbart/gst-go"
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

		id_counter, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/id_counter", &ebpf.LoadPinOptions{})
		if err != nil {
			panic(err)
		}
		err = id_counter.Update(uint32(0), uint32(0), 0)
		if err != nil {
			panic(err)
		}
	}

	c, err := quic.DialAddr(context.Background(), video_server_address,
		&tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"moq-00"},
		}, &quic.Config{
			EnableDatagrams:            true,
			MaxIncomingStreams:         1 << 60,
			MaxStreamReceiveWindow:     1 << 60,
			MaxIncomingUniStreams:      1 << 60,
			MaxConnectionReceiveWindow: 1 << 60,
		})
	if err != nil {
		panic(err)
	}

	client_sess, err := moqtransport.NewClientSession(quicmoq.New(c), moqtransport.DeliveryRole, true)
	if err != nil {
		return err
	}
	fmt.Println("moq peer connected")
	a, err := client_sess.ReadAnnouncement(context.Background())
	if err != nil {
		return err
	}
	log.Printf("got announcement of namespace %v", a.Namespace())

	subscriptionList := make([]*moqtransport.SendSubscription, 0)
	a.Accept()

	client_sub, err := client_sess.Subscribe(context.Background(), 0, 0, a.Namespace(), "video", "")
	if err != nil {
		return err
	}

	player_chan := make(chan []byte)
	if relay_playing {
		go relay_player(player_chan)
	}

	var cache [][]byte

	go func(sub *moqtransport.ReceiveSubscription, player_chan chan []byte) {
		for {
			buf := make([]byte, 64_000)
			n, err := client_sub.Read(buf)
			if err != nil {
				log.Printf("error on read: %v", err)
				return
			}
			if n == 0 {
				continue
			}

			if relay_playing {
				fmt.Println("Received", n, "bytes")
				player_chan <- buf[:n]
				fmt.Println("Sent", n, "bytes to player")
			}

			if relay_caching {
				cache = append(cache, buf[:n])
				if len(cache) > cache_packet_size {
					cache = cache[1:] // TODO: handle with deque?
				}
			}

			if relay_passing_on {
				for i, cs := range subscriptionList {
					fmt.Println("Trying to send", n, "bytes to peer", i)
					stream, err := cs.NewObjectStream(0, 0, 0)
					if err != nil {
						log.Printf("error on NewObjectStream: %v", err)
						return
					}
					n, err := stream.Write(buf[:n])
					if err != nil {
						log.Printf("error on write: %v", err)
						return
					}
					fmt.Println("Sent", n, "bytes to peer", i)
					err = stream.Close()
					if err != nil {
						log.Printf("error on close: %v", err)
						return
					}
				}
			}
		}
	}(client_sub, player_chan)

	ctx := context.Background()

	tlsConfig := generateTLSConfig(false)

	listener, err := quic.ListenAddr(relay_server_address, tlsConfig, generateQUICConfig())
	if err != nil {
		return err
	}
	conn, err := listener.Accept(ctx)
	if err != nil {
		return err
	}

	// Run goroutine that will register the packets sent by the BPF program
	go registerBPFPacket(conn)

	go func(conn quic.Connection) {
		if !relay_printing_rtt {
			return
		}
		for {
			stats := conn.GetRTTStats()

			fmt.Println("Min RTT:", stats.MinRTT.Milliseconds())
			fmt.Println("Latest RTT:", stats.LatestRTT.Milliseconds())
			fmt.Println("Smoothed RTT:", stats.SmoothedRTT.Milliseconds())
			fmt.Println("Max RTT Variance:", stats.RTTVariance.Milliseconds())
			fmt.Println("Max Ack Delay:", stats.MaxAckDelay.Milliseconds())
			fmt.Print("\n-----------------------------------------\n")

			time.Sleep(1 * time.Second)
		}
	}(conn)

	server_sess, err := moqtransport.NewServerSession(quicmoq.New(conn), true)
	if err != nil {
		return err
	}

	log.Printf("handling new peer")
	go func() {
		var a *moqtransport.Announcement
		a, err = server_sess.ReadAnnouncement(ctx)
		if err != nil {
			return
		}
		log.Printf("got announcement: %v", a.Namespace())
		a.Reject(0, "relay does not accept announcements")
	}()

	go func() {
		if err = server_sess.Announce(ctx, "video"); err != nil {
			return
		}
		log.Printf("announced video namespace")
	}()

	for {
		server_sub, err := server_sess.ReadSubscription(ctx)
		if err != nil {
			return err
		}
		log.Printf("handling subscription to track %s/%s", server_sub.Namespace(), server_sub.Trackname())
		if server_sub.Trackname() != "video" {
			err = errors.New("unknown trackname")
			server_sub.Reject(0, err.Error())
			return err
		}
		server_sub.Accept()
		log.Printf("subscription accepted")

		// TODO: maybe use a ring buffer here?
		// TODO: maybe copy cache and only send copy?
		// TODO: if copying, increment the client counter before
		// TODO: hand to avoid missing packets.
		if relay_caching {
			for _, buf := range cache {
				stream, err := server_sub.NewObjectStream(0, 0, 0)
				if err != nil {
					log.Printf("error on NewObjectStream: %v", err)
					panic(err)
				}
				_, err = stream.Write(buf)
				if err != nil {
					log.Printf("error on write: %v", err)
					panic(err)
				}
				err = stream.Close()
				if err != nil {
					log.Printf("error on close: %v", err)
					panic(err)
				}
			}
		}

		subscriptionList = append(subscriptionList, server_sub)

		// Increment client counter
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
		}

	}
}

func relay_player(recv_chan chan []byte) error {
	closeCh := make(chan struct{})

	p := new(gst.Pipeline)
	err := error(nil)
	if test_video {
		p, err = gst.NewPipeline("appsrc name=src ! video/x-vp8 ! vp8dec ! video/x-raw,width=480,height=320,framerate=30/1 ! autovideosink")
	} else {
		launch_str := `
			appsrc name=src
			! video/x-vp8 ! vp8dec 
			! video/x-raw, format=(string)I420, width=(int)1280, height=(int)720, interlace-mode=(string)progressive, pixel-aspect-ratio=(fraction)1/1, chroma-site=(string)mpeg2, colorimetry=(string)bt709, framerate=(fraction)25/1 
			! autovideosink
		`
		p, err = gst.NewPipeline(launch_str)
	}
	if err != nil {
		panic(err)
	}
	p.SetEOSHandler(func() {
		p.Stop()
		closeCh <- struct{}{}
	})
	p.SetErrorHandler(func(err error) {
		log.Println(err)
		p.Stop()
		closeCh <- struct{}{}
	})
	p.Start()
	log.Println("starting pipeline")
	go func() {
		for {
			buf := <-recv_chan
			n := len(buf)
			fmt.Println("Received", n, "bytes")
			_, err = p.Write(buf[:n])
			if err != nil {
				log.Printf("error on write: %v", err)
				p.SendEOS()
			}
		}
	}()

	ml := gst.NewMainLoop()
	go func() {
		<-closeCh
		ml.Stop()
	}()
	ml.Run()
	return nil
}
