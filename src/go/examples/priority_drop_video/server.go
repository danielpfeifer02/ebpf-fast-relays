package main

import (
	"context"
	"fmt"
	"log"

	"common.com/common"
)

// TODO: error as return value not needed?
func server() error {

	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	done := common.StartSignalHandler()

	go func(ctx context.Context) {
		sender, err := newSender(ctx, video_server_address)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Starting sender")
		sender.start()
		<-ctx.Done()
		err = sender.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(ctx)

	<-done
	return nil
}

// func server_old() error {

// 	tlsConfig := generateTLSConfig(false)
// 	listener, err := quic.ListenAddr(video_server_address, tlsConfig, generateQUICConfig())
// 	if err != nil {
// 		return err
// 	}

// 	ctx := context.Background()

// 	conn, err := listener.Accept(ctx)
// 	if err != nil {
// 		return err
// 	}
// 	s, err := moqtransport.NewServerSession(quicmoq.New(conn), true)
// 	if err != nil {
// 		return err
// 	}

// 	log.Printf("handling new peer")
// 	go func() {
// 		var a *moqtransport.Announcement
// 		a, err = s.ReadAnnouncement(ctx)
// 		if err != nil {
// 			return
// 		}
// 		log.Printf("got announcement: %v", a.Namespace())
// 		a.Reject(0, "server does not accept announcements")
// 	}()

// 	go func() {
// 		if err = s.Announce(ctx, "video"); err != nil {
// 			return
// 		}
// 		log.Printf("announced video namespace")
// 	}()

// 	sub, err := s.ReadSubscription(ctx)
// 	if err != nil {
// 		return err
// 	}
// 	log.Printf("handling subscription to track %s/%s", sub.Namespace(), sub.Trackname())
// 	if sub.Trackname() != "video" {
// 		err = errors.New("unknown trackname")
// 		sub.Reject(0, err.Error())
// 		return err
// 	}
// 	sub.Accept()
// 	log.Printf("subscription accepted")

// 	ctx, cancel := context.WithCancelCause(ctx)
// 	defer cancel(nil)

// 	p := new(gst.Pipeline)
// 	if test_video {
// 		p, err = gst.NewPipeline("videotestsrc is-live=true ! video/x-raw,width=480,height=320,framerate=30/1 ! clocksync ! vp8enc name=encoder target-bitrate=10000000 cpu-used=16 deadline=1 keyframe-max-dist=10 ! appsink name=appsink")
// 	} else {
// 		launch_str := `
// 			filesrc location=../../../video/example.mp4
// 			! decodebin
// 			! video/x-raw, format=(string)I420, width=(int)1280, height=(int)720, interlace-mode=(string)progressive, pixel-aspect-ratio=(fraction)1/1, chroma-site=(string)mpeg2, colorimetry=(string)bt709, framerate=(fraction)25/1
// 			! clocksync
// 			! vp8enc name=encoder target-bitrate=10000000 cpu-used=16 deadline=1 keyframe-max-dist=10
// 			! appsink name=appsink
// 		`
// 		p, err = gst.NewPipeline(launch_str)

// 		// gst-launch-1.0 filesrc location=src/video/example.mp4 ! decodebin ! "video/x-raw, format=(string)I420, width=(int)1280, height=(int)720, interlace-mode=(string)progressive, pixel-aspect-ratio=(fraction)1/1, chroma-site=(string)mpeg2, colorimetry=(string)bt709, framerate=(fraction)25/1" ! clocksync ! vp8enc name=encoder target-bitrate=10000000 cpu-used=16 deadline=1 keyframe-max-dist=10 ! udpsink host=127.0.0.1 port=5600
// 		// gst-launch-1.0 udpsrc port=5600 ! video/x-vp8 ! vp8dec ! "video/x-raw, format=(string)I420, width=(int)1280, height=(int)720, interlace-mode=(string)progressive, pixel-aspect-ratio=(fraction)1/1, chroma-site=(string)mpeg2, colorimetry=(string)bt709, framerate=(fraction)25/1" ! autovideosink
// 	}

// 	if err != nil {
// 		err = errors.New("internal error")
// 		sub.Reject(0, err.Error())
// 		return err
// 	}
// 	p.SetEOSHandler(func() {
// 		p.Stop()
// 		cancel(errors.New("EOS"))
// 	})
// 	p.SetErrorHandler(func(err error) {
// 		log.Println(err)
// 		p.Stop()
// 		cancel(err)
// 	})
// 	p.SetBufferHandler(func(b gst.Buffer) {
// 		stream, err := sub.NewObjectStream(0, 0, 0)
// 		if err != nil {
// 			cancel(err)
// 			return
// 		}
// 		n, err := stream.Write(b.Bytes)
// 		if err != nil {
// 			cancel(err)
// 			return
// 		}
// 		fmt.Println("Sent", n, "bytes to peer")
// 		if err := stream.Close(); err != nil {
// 			cancel(err)
// 			return
// 		}
// 	})
// 	p.Start()

// 	<-ctx.Done()

// 	return context.Cause(ctx)

// }
