package main

import (
	"context"
	"errors"
	"log"

	moqtransport "github.com/danielpfeifer02/priority-moqtransport"
	"github.com/danielpfeifer02/priority-moqtransport/quicmoq"
	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/mengelbart/gst-go"
)

func client() error {

	ctx := context.Background()

	conn, err := quic.DialAddr(ctx, video_server_address, generateTLSConfig(false), generateQUICConfig())
	if err != nil {
		return err
	}
	s, err := moqtransport.NewClientSession(quicmoq.New(conn), moqtransport.DeliveryRole, true)
	if err != nil {
		return err
	}
	a, err := s.ReadAnnouncement(ctx)
	if err != nil {
		return err
	}
	log.Printf("got announcement of namespace %v", a.Namespace())
	a.Accept()
	sub, err := s.Subscribe(ctx, 0, 0, a.Namespace(), "video", "")
	if err != nil {
		return err
	}
	log.Printf("subscribed to %v/%v", a.Namespace(), "video")
	ctx, cancel := context.WithCancelCause(ctx)

	p := new(gst.Pipeline)
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
		return err
	}
	p.SetEOSHandler(func() {
		p.Stop()
		cancel(errors.New("EOS"))
	})
	p.SetErrorHandler(func(err error) {
		log.Println(err)
		p.Stop()
		cancel(err)
	})
	p.Start()

	go func() {
		for {
			log.Println("reading from track")
			buf := make([]byte, 64_000)
			n, err := sub.Read(buf)
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

	<-ctx.Done()

	return context.Cause(ctx)
}
