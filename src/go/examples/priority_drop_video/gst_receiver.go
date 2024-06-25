package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	moqtransport "github.com/danielpfeifer02/priority-moqtransport"
	"github.com/danielpfeifer02/priority-moqtransport/quicmoq"
	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/go-gst/go-gst/gst"
	"github.com/go-gst/go-gst/gst/app"
)

type receiver struct {
	pipeline  *gst.Pipeline
	session   *moqtransport.Session
	ctx       context.Context
	cancelCtx context.CancelFunc
}

func newReceiver(ctx context.Context, addr string) (*receiver, error) {

	c, err := quic.DialAddr(ctx, addr,
		&tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"moq-00"},
		}, &quic.Config{
			EnableDatagrams:            true,
			MaxIdleTimeout:             5 * time.Minute,
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
		return nil, err
	}
	fmt.Println("moq peer connected")
	a, err := client_sess.ReadAnnouncement(context.Background())
	if err != nil {
		return nil, err
	}
	log.Printf("got announcement of namespace %v", a.Namespace())

	// subscriptionList := make([]*moqtransport.SendSubscription, 0)
	a.Accept()

	client_sub, err := client_sess.Subscribe(context.Background(), 0, 0, a.Namespace(), "video", "")
	if err != nil {
		return nil, err
	}
	pipeline, err := createReceivePipeline(client_sub)
	if err != nil {
		return nil, err
	}
	ctx, cancelCtx := context.WithCancel(context.Background())
	r := &receiver{
		pipeline:  pipeline,
		session:   client_sess,
		ctx:       ctx,
		cancelCtx: cancelCtx,
	}
	return r, nil
}

func (r *receiver) start() error {
	bus := r.pipeline.GetPipelineBus()
	go func() {
		<-r.ctx.Done()
		r.pipeline.SendEvent(gst.NewEOSEvent())
	}()
	r.pipeline.SetState(gst.StatePlaying)
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

func (r *receiver) Close() error {
	r.cancelCtx()
	return nil
}

func createReceivePipeline(flow *moqtransport.ReceiveSubscription) (*gst.Pipeline, error) {

	send_chan := make(chan []byte)
	pipeline, err := createReceivePipelineFromChannel(send_chan)
	if err != nil {
		return nil, err
	}
	go func() { // TODO: graceful shutdown of this goroutine?
		for {
			buf := make([]byte, 64_000)
			n, err := flow.Read(buf)
			if err != nil {
				panic(err)
			}
			if n == 0 {
				continue
			}
			fmt.Println("Received", n, "bytes")
			send_chan <- buf[:n]
		}
	}()

	return pipeline, nil

}

// TODO: remove
// var _ = `
// gst-launch-1.0 appsrc name=src ! rtpjitterbuffer ! application/x-rtp,media=\(string\)video,clockrate=\(int\)90000,encoding-name=\(string\)VP8,payload=\(int\)96 ! rtpvp8depay ! video/x-vp8 ! vp8dec ! video/x-raw,format=\(string\)I420,width=\(int\)1280,height=\(int\)720,interlace-mode=\(string\)progressive,pixel-aspect-ratio=\(fraction\)1/1,chroma-site=\(string\)mpeg2,colorimetry=\(string\)bt709,framerate=\(fraction\)25/1 ! videoconvert ! clocksync ! autovideosink
// gst-launch-1.0 filesrc location=../../../video/example.mp4 ! decodebin ! video/x-raw,format=\(string\)I420,width=\(int\)1280,height=\(int\)720,interlace-mode=\(string\)progressive,pixel-aspect-ratio=\(fraction\)1/1,chroma-site=\(string\)mpeg2,colorimetry=\(string\)bt709,framerate=\(fraction\)25/1 ! clocksync ! vp8enc name=encoder target-bitrate=10000000 cpu-used=16 deadline=1 keyframe-max-dist=10 ! rtpvp8pay mtu=64000 ! appsink name=appsink
//
// `

func createReceivePipelineFromChannel(recv_chan chan []byte) (*gst.Pipeline, error) {
	// gst.Init(nil)

	// TODO: appsrc name=src is-live=true or not?
	pstr := `
		appsrc name=src
		! video/x-vp8 
		! vp8dec 
		! video/x-raw, format=(string)I420, width=(int)1280, height=(int)720, 
		  interlace-mode=(string)progressive, pixel-aspect-ratio=(fraction)1/1, 
		  chroma-site=(string)mpeg2, colorimetry=(string)bt709, framerate=(fraction)25/1

		! autovideosink
	`

	pipeline, err := gst.NewPipelineFromString(pstr)
	if err != nil {
		return nil, err
	}

	src := app.SrcFromElement(getElementByName(pipeline, "src"))

	src.SetCallbacks(&app.SourceCallbacks{
		NeedDataFunc: func(self *app.Source, length uint) {
			buf := <-recv_chan

			// Here we retrieve the presentation timestamp from the beginning of the buffer.
			ts_bytes := buf[:8]
			buf = buf[8:]
			ts_i64 := uint64(binary.BigEndian.Uint64(ts_bytes))

			n := len(buf)
			log.Printf("read %v bytes\n", n)
			buffer := gst.NewBufferWithSize(int64(n))

			// Here we set the presentation timestamp of the buffer again.
			ts_i64_gst_ct := gst.ClockTime(ts_i64)
			buffer.SetPresentationTimestamp(ts_i64_gst_ct)

			buffer.Map(gst.MapWrite).WriteData(buf[:n])
			buffer.Unmap()

			self.PushBuffer(buffer)
		},
	})
	return pipeline, nil
}
