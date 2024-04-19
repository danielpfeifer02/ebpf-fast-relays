package main

import (
	"context"
	"log"

	moqtransport "github.com/danielpfeifer02/priority-moqtransport"
	"github.com/mengelbart/gst-go"
)

func client() error {
	announcementCh := make(chan string)
	closeCh := make(chan struct{})

	c, err := moqtransport.DialQUIC(context.Background(), relay_server_address)
	if err != nil {
		panic(err)
	}

	log.Println("moq peer connected")
	c.OnAnnouncement(func(s string) error {
		log.Printf("handling announcement of track %v", s)
		announcementCh <- s
		return nil
	})

	trackname := <-announcementCh
	log.Printf("got announcement: %v", trackname)
	p, err := gst.NewPipeline("appsrc name=src ! multipartdemux ! jpegdec ! autovideosink")
	if err != nil {
		panic(err)
	}
	t, err := c.Subscribe(trackname)
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
			log.Println("reading from track")
			buf := make([]byte, 64_000)
			n, err := t.Read(buf)
			if err != nil {
				log.Printf("error on read: %v", err)
				p.SendEOS()
			}
			log.Printf("writing %v bytes from stream to pipeline", n)
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
