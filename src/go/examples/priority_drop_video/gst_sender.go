package main

import (
	"context"
	"encoding/binary"
	"errors"
	"log"

	moqtransport "github.com/danielpfeifer02/priority-moqtransport"
	"github.com/danielpfeifer02/priority-moqtransport/quicmoq"
	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/go-gst/go-gst/gst"
	"github.com/go-gst/go-gst/gst/app"
)

type sender struct {
	pipeline  *gst.Pipeline
	session   *moqtransport.Session
	ctx       context.Context
	cancelCtx context.CancelFunc
}

func newSender(ctx context.Context, addr string) (*sender, error) {

	tlsConfig := generateTLSConfig(false)
	listener, err := quic.ListenAddr(addr, tlsConfig, generateQUICConfig())
	if err != nil {
		return nil, err
	}

	conn, err := listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	session, err := moqtransport.NewServerSession(quicmoq.New(conn), true)
	if err != nil {
		return nil, err
	}

	log.Printf("handling new peer")
	go func() {
		var a *moqtransport.Announcement
		a, err = session.ReadAnnouncement(ctx)
		if err != nil {
			return
		}
		log.Printf("got announcement: %v", a.Namespace())
		a.Reject(0, "server does not accept announcements")
	}()

	go func() {
		if err = session.Announce(ctx, "video"); err != nil {
			return
		}
		log.Printf("announced video namespace")
	}()

	sub, err := session.ReadSubscription(ctx)
	if err != nil {
		return nil, err
	}
	log.Printf("handling subscription to track %s/%s", sub.Namespace(), sub.Trackname())
	if sub.Trackname() != "video" {
		err = errors.New("unknown trackname")
		sub.Reject(0, err.Error())
		return nil, err
	}
	sub.Accept()
	log.Printf("subscription accepted")
	pipeline, err := createSendPipeline(sub)
	if err != nil {
		return nil, err
	}
	ctx, cancelCtx := context.WithCancel(context.Background())
	s := &sender{
		pipeline:  pipeline,
		session:   session,
		ctx:       ctx,
		cancelCtx: cancelCtx,
	}
	return s, nil
}

func (s *sender) start() error {
	bus := s.pipeline.GetPipelineBus()
	go func() {
		<-s.ctx.Done()
		s.pipeline.SendEvent(gst.NewEOSEvent())
	}()
	s.pipeline.SetState(gst.StatePlaying)
	for {
		msg := bus.TimedPop(gst.ClockTimeNone)
		if msg == nil {
			break
		}
		if err := handleMessage(msg); err != nil {
			return err
		}
	}
	return nil
}

func (s *sender) Close() error {
	s.cancelCtx()
	return nil
}

func createSendPipeline(flow *moqtransport.SendSubscription) (*gst.Pipeline, error) {
	// gst.Init(nil)

	pstr := `
			filesrc location=../../../video/example.mp4
			! decodebin
			! video/x-raw, format=(string)I420, width=(int)1280, height=(int)720, 
			  interlace-mode=(string)progressive, pixel-aspect-ratio=(fraction)1/1, 
			  chroma-site=(string)mpeg2, colorimetry=(string)bt709, framerate=(fraction)25/1
			! clocksync 
			! vp8enc name=encoder target-bitrate=10000000 cpu-used=16 deadline=1 
			  keyframe-max-dist=2
			
			! appsink name=appsink
	`

	pipeline, err := gst.NewPipelineFromString(pstr)
	if err != nil {
		return nil, err
	}

	sink := app.SinkFromElement(getElementByName(pipeline, "appsink"))

	sink.SetCallbacks(&app.SinkCallbacks{
		NewSampleFunc: func(sink *app.Sink) gst.FlowReturn {
			sample := sink.PullSample()
			if sample == nil {
				return gst.FlowEOS
			}
			buffer := sample.GetBuffer()
			if buffer == nil {
				return gst.FlowError
			}
			samples := buffer.Map(gst.MapRead).AsUint8Slice()
			defer buffer.Unmap()

			stream, err := flow.NewObjectStream(0, 0, 0)
			if err != nil {
				return gst.FlowError
			}

			// Here we add the presentation timestamp to the beginning of the buffer.
			// This is a little hacky but needed at the sink side to be able to
			// reconstruct the video stream correctly (even if packets are dropped).
			pres_ts := buffer.PresentationTimestamp()
			ts_arr := make([]byte, 8)
			binary.BigEndian.PutUint64(ts_arr, uint64(pres_ts))
			samples = append(ts_arr, samples...)

			n, err := stream.Write(samples)
			if err != nil {
				return gst.FlowError
			}
			log.Printf("buffer len: %v, written: %v\n", len(samples), n)

			err = stream.Close()
			if err != nil {
				return gst.FlowError
			}
			return gst.FlowOK
		},
	})
	return pipeline, nil
}
