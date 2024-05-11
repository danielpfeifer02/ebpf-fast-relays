package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	moqtransport "github.com/danielpfeifer02/priority-moqtransport"
	"github.com/danielpfeifer02/priority-moqtransport/quicmoq"
	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/mengelbart/gst-go"
)

func server() error {

	tlsConfig := video_generateTLSConfig(true)
	listener, err := quic.ListenAddr(video_server_address, tlsConfig, &quic.Config{
		EnableDatagrams:            true,
		MaxIncomingStreams:         1 << 60,
		MaxStreamReceiveWindow:     1 << 60,
		MaxIncomingUniStreams:      1 << 60,
		MaxConnectionReceiveWindow: 1 << 60,
	})
	if err != nil {
		return err
	}

	ctx := context.Background()

	conn, err := listener.Accept(ctx)
	if err != nil {
		return err
	}
	s, err := moqtransport.NewServerSession(quicmoq.New(conn), true)
	if err != nil {
		return err
	}

	log.Printf("handling new peer")
	go func() {
		var a *moqtransport.Announcement
		a, err = s.ReadAnnouncement(ctx)
		if err != nil {
			return
		}
		log.Printf("got announcement: %v", a.Namespace())
		a.Reject(0, "server does not accept announcements")
	}()

	go func() {
		if err = s.Announce(ctx, "video"); err != nil {
			return
		}
		log.Printf("announced video namespace")
	}()

	sub, err := s.ReadSubscription(ctx)
	if err != nil {
		return err
	}
	log.Printf("handling subscription to track %s/%s", sub.Namespace(), sub.Trackname())
	if sub.Trackname() != "video" {
		err = errors.New("unknown trackname")
		sub.Reject(0, err.Error())
		return err
	}
	sub.Accept()
	log.Printf("subscription accepted")

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	p, err := gst.NewPipeline("videotestsrc is-live=true ! video/x-raw,width=480,height=320,framerate=30/1 ! clocksync ! vp8enc name=encoder target-bitrate=10000000 cpu-used=16 deadline=1 keyframe-max-dist=10 ! appsink name=appsink")
	if err != nil {
		err = errors.New("internal error")
		sub.Reject(0, err.Error())
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
	p.SetBufferHandler(func(b gst.Buffer) {
		stream, err := sub.NewObjectStream(0, 0, 0)
		if err != nil {
			cancel(err)
			return
		}
		n, err := stream.Write(b.Bytes)
		if err != nil {
			cancel(err)
			return
		}
		fmt.Println("Sent", n, "bytes to peer")
		if err := stream.Close(); err != nil {
			cancel(err)
			return
		}
	})
	p.Start()

	<-ctx.Done()

	return context.Cause(ctx)

}
