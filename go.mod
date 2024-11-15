module github.com/danielpfeifer02/adaptive_moq

go 1.22.0

require (
	common.com/common v0.0.0
	fyne.io/fyne/v2 v2.4.5
	github.com/cilium/ebpf v0.15.0
	github.com/danielpfeifer02/priority-moqtransport v0.1.1-6
	github.com/danielpfeifer02/quic-go-prio-packs v0.41.0-28
	github.com/go-gst/go-gst v1.0.0
	github.com/go-sql-driver/mysql v1.8.1
	github.com/mengelbart/gst-go v0.0.4
	github.com/x1m3/priorityQueue v0.0.0-20180318192439-29f82ba34a27
)

require golang.org/x/crypto v0.23.0 // indirect

replace github.com/danielpfeifer02/priority-moqtransport v0.1.1-6 => ../gst-prio-moq-app/priority-moqtransport

replace github.com/danielpfeifer02/quic-go-prio-packs v0.41.0-28 => ../quic-go-prio-packs

replace common.com/common v0.0.0 => ./src/go/common

replace golang.com/x/crypto v0.23.0 => ../crypto

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	fyne.io/systray v1.10.1-0.20231115130155-104f5ef7839e // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/francoispqt/gojay v1.2.13 // indirect
	github.com/fredbi/uri v1.0.0 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/fyne-io/gl-js v0.0.0-20220119005834-d2da28d9ccfe // indirect
	github.com/fyne-io/glfw-js v0.0.0-20220120001248-ee7290d23504 // indirect
	github.com/fyne-io/image v0.0.0-20220602074514-4956b0afb3d2 // indirect
	github.com/go-gl/gl v0.0.0-20211210172815-726fda9656d6 // indirect
	github.com/go-gl/glfw/v3.3/glfw v0.0.0-20240306074159-ea2d69986ecb // indirect
	github.com/go-gst/go-glib v1.0.0 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/go-text/render v0.1.0 // indirect
	github.com/go-text/typesetting v0.1.0 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/google/pprof v0.0.0-20230821062121-407c9e7a662f // indirect
	github.com/gopherjs/gopherjs v1.17.2 // indirect
	github.com/jsummers/gobmp v0.0.0-20151104160322-e2ba15ffa76e // indirect
	github.com/mattn/go-pointer v0.0.1 // indirect
	github.com/onsi/ginkgo/v2 v2.12.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/srwiley/oksvg v0.0.0-20221011165216-be6e8873101c // indirect
	github.com/srwiley/rasterx v0.0.0-20220730225603-2ab79fcdd4ef // indirect
	github.com/stretchr/testify v1.8.4 // indirect
	github.com/tevino/abool v1.2.0 // indirect
	github.com/yuin/goldmark v1.5.5 // indirect
	go.uber.org/mock v0.4.0 // indirect; indirect// indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/image v0.11.0 // indirect
	golang.org/x/mobile v0.0.0-20230531173138-3c911d8e3eda // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/net v0.25.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
	golang.org/x/text v0.15.0 // indirect
	golang.org/x/tools v0.21.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	honnef.co/go/js/dom v0.0.0-20210725211120-f030747120f2 // indirect
)
