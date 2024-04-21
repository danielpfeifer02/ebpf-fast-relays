package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	moqtransport "github.com/danielpfeifer02/priority-moqtransport"
	"github.com/mengelbart/gst-go"
)

func server() error {
	s := moqtransport.Server{
		Handler: moqtransport.PeerHandlerFunc(func(p *moqtransport.Peer) {
			log.Println("handling new peer")
			defer log.Println("XXX")
			p.OnAnnouncement(func(s string) error {
				log.Printf("got announcement: %v", s)
				return nil
			})
			if err := p.Announce("video"); err != nil {
				log.Printf("failed to announce video: %v", err)
			}
			log.Println("announced video namespace")
			p.OnSubscription(func(s string, st *moqtransport.SendTrack) (uint64, time.Duration, error) {
				log.Printf("handling subscription to track %s", s)
				if s != "video" {
					return 0, 0, errors.New("unknown trackname")
				}
				p, err := gst.NewPipeline("videotestsrc ! queue ! videoconvert ! jpegenc ! multipartmux ! appsink name=appsink")
				if err != nil {
					log.Fatal(err)
				}
				p.SetBufferHandler(func(b gst.Buffer) {
					if _, err := st.Write(b.Bytes); err != nil {
						panic(err)
					}
				})
				p.SetEOSHandler(func() {
					p.Stop()
				})
				p.SetErrorHandler(func(err error) {
					log.Println(err)
					p.Stop()
				})
				p.Start()
				return 0, 0, nil
			})
			fmt.Println("Peer is set up")
		}),
		TLSConfig: video_generateTLSConfig(false),
	}
	if err := s.ListenQUIC(context.Background(), video_server_address); err != nil {
		panic(err)
	}
	return nil
}
