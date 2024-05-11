package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"

	moqtransport "github.com/danielpfeifer02/priority-moqtransport"
	"github.com/danielpfeifer02/priority-moqtransport/quicmoq"
	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/mengelbart/gst-go"
)

func client() error {

	ctx := context.Background()

	conn, err := quic.DialAddr(ctx, relay_server_address, &tls.Config{
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
	p, err := gst.NewPipeline("appsrc name=src ! video/x-vp8 ! vp8dec ! video/x-raw,width=480,height=320,framerate=30/1 ! autovideosink")
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
