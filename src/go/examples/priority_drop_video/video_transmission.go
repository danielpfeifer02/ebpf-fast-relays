package main

import (
	"log"

	"github.com/go-gst/go-gst/gst"
	"github.com/go-gst/go-gst/gst/app"
)

const video_server_address = "192.168.10.1:4242"
const relay_server_address = "192.168.11.2:4242"

func video_main(user string) {

	gst.Init(nil)
	defer gst.Deinit()

	if user == "server" {
		if err := server(); err != nil {
			log.Fatal(err)
		}
		return
	} else if user == "relay" {
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
