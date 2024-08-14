package main

import (
	"log"
	"os"
	"runtime/pprof"
	"time"

	"github.com/go-gst/go-gst/gst"
	"github.com/go-gst/go-gst/gst/app"
)

const video_server_address = "192.168.10.1:4242"
const relay_server_address = "192.168.11.2:4242"

func video_main(user string) {

	gst.Init(nil)

	if user == "server" {

		// // Check if the number of goroutines changed after the GUI
		// // TODO: necessary?
		// before := runtime.NumGoroutine()

		// Not ideal here, but if this function is called in the nested
		// structure of the server() function it gets non-obvious to
		// verify that this is always called in the main goroutine.
		if server_changing_sender_specs {
			change_sender_data_specs()
		}

		// after := runtime.NumGoroutine()
		// if before != after {
		// 	panic("Number of goroutines changed from " + fmt.Sprint(before) + " to " + fmt.Sprint(after) + " after GUI!")
		// }

		if err := server(); err != nil {
			log.Fatal(err)
		}
		return
	} else if user == "relay" {

		if log_cpu_performance {
			f, err := os.Create("build/prof/cpu.prof")
			if err != nil {
				panic(err)
			}
			pprof.StartCPUProfile(f)
			go func() {
				time.Sleep(cpu_log_time)
				pprof.StopCPUProfile()
				panic("CPU profile stopped")
			}()
		}

		// Not ideal here, but if this function is called in the nested
		// structure of the relay() function it gets non-obvious to
		// verify that this is always called in the main goroutine.
		if relay_changing_sender_specs {
			change_sender_data_specs()
		}
		if err := relay(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := client(); err != nil {
		log.Fatal(err)
	}
}

func handleMessage(msg *gst.Message) error {
	switch msg.Type() {
	case gst.MessageEOS:
		return app.ErrEOS
	case gst.MessageError:
		return msg.ParseError()
	}
	return nil
}
