package main

import (
	"log"

	"github.com/mengelbart/gst-go"
)

const video_server_address = "192.168.10.1:4242"
const relay_server_address = "192.168.11.2:4242"

func video_main(user string) {

	gst.GstInit()
	defer gst.GstDeinit()

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
