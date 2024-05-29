package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func client() error {

	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	done := make(chan struct{}, 1)

	go func() {
		receiver, err := newReceiver(ctx, relay_server_address)
		if err != nil {
			log.Fatal(err)
		}
		receiver.start()
		<-ctx.Done()
		err = receiver.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	<-done
	return nil

}

// func client_old() error {

// 	ctx := context.Background()

// 	conn, err := quic.DialAddr(ctx, relay_server_address, generateTLSConfig(false), generateQUICConfig())
// 	if err != nil {
// 		return err
// 	}
// 	s, err := moqtransport.NewClientSession(quicmoq.New(conn), moqtransport.DeliveryRole, true)
// 	if err != nil {
// 		return err
// 	}
// 	a, err := s.ReadAnnouncement(ctx)
// 	if err != nil {
// 		return err
// 	}
// 	log.Printf("got announcement of namespace %v", a.Namespace())
// 	a.Accept()
// 	sub, err := s.Subscribe(ctx, 0, 0, a.Namespace(), "video", "")
// 	if err != nil {
// 		return err
// 	}
// 	log.Printf("subscribed to %v/%v", a.Namespace(), "video")
// 	ctx, cancel := context.WithCancelCause(ctx)

// 	p := new(gst.Pipeline)
// 	if test_video {
// 		p, err = gst.NewPipeline("appsrc name=src ! video/x-vp8 ! vp8dec ! video/x-raw,width=480,height=320,framerate=30/1 ! autovideosink")
// 	} else {
// 		launch_str := `
// 			appsrc name=src
// 			! video/x-vp8 ! vp8dec
// 			! video/x-raw, format=(string)I420, width=(int)1280, height=(int)720, interlace-mode=(string)progressive, pixel-aspect-ratio=(fraction)1/1, chroma-site=(string)mpeg2, colorimetry=(string)bt709, framerate=(fraction)25/1
// 			! autovideosink
// 		`
// 		p, err = gst.NewPipeline(launch_str)
// 	}
// 	if err != nil {
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
// 	p.Start()

// 	go func() {
// 		for {
// 			log.Println("reading from track")
// 			buf := make([]byte, 64_000)
// 			n, err := sub.Read(buf)
// 			if err != nil {
// 				log.Printf("error on read: %v", err)
// 				p.SendEOS()
// 			}
// 			log.Printf("writing %v bytes from stream to pipeline", n)
// 			_, err = p.Write(buf[:n])
// 			if err != nil {
// 				log.Printf("error on write: %v", err)
// 				p.SendEOS()
// 			}
// 		}
// 	}()

// 	<-ctx.Done()

// 	return context.Cause(ctx)
// }
