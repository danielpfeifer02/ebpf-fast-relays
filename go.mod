module github.com/danielpfeifer02/adaptive_moq

go 1.22.0

require (
	github.com/cilium/ebpf v0.13.2
	github.com/danielpfeifer02/priority-moqtransport v0.1.1-6
	github.com/danielpfeifer02/quic-go-prio-packs v0.41.0-28
	github.com/gammazero/deque v0.2.1
	github.com/mengelbart/gst-go v0.0.4
)

replace github.com/danielpfeifer02/priority-moqtransport v0.1.1-6 => ../gst-prio-moq-app/priority-moqtransport

replace github.com/danielpfeifer02/quic-go-prio-packs v0.41.0-28 => ../quic-go-prio-packs

require (
	github.com/francoispqt/gojay v1.2.13 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/pprof v0.0.0-20230821062121-407c9e7a662f // indirect
	github.com/onsi/ginkgo/v2 v2.12.0 // indirect
	go.uber.org/mock v0.4.0 // indirect
	golang.org/x/crypto v0.22.0 // indirect
	golang.org/x/exp v0.0.0-20240416160154-fe59bbe5cc7f // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/net v0.24.0 // indirect
	golang.org/x/sys v0.19.0 // indirect
	golang.org/x/tools v0.20.0 // indirect
)
