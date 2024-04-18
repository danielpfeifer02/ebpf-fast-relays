module github.com/danielpfeifer02/adaptive_moq

go 1.22.0

require (
	github.com/cilium/ebpf v0.13.2
	github.com/danielpfeifer02/priority-moqtransport v0.1.1-3
	github.com/danielpfeifer02/quic-go-prio-packs v0.41.0-26
	github.com/mengelbart/gst-go v0.0.4
)

// replace github.com/danielpfeifer02/priority-moqtransport v0.1.1-3 => ../gst-prio-moq-app/priority-moqtransport

// github.com/danielpfeifer02/priority-moqtransport/varint v0.1.0
//replace github.com/danielpfeifer02/priority-moqtransport/varint v0.1.0 => ./priority-moqtransport/varint

// github.com/mengelbart/moqtransport v0.1.1-0.20231007110949-d6b0470c8219
// github.com/danielpfeifer02/quic-go-no-crypto v0.41.0-1
// github.com/danielpfeifer02/quic-go-prio-packs v0.41.0-5

require (
	github.com/francoispqt/gojay v1.2.13 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/google/pprof v0.0.0-20230821062121-407c9e7a662f // indirect
	github.com/onsi/ginkgo/v2 v2.12.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/quic-go/qtls-go1-20 v0.3.3 // indirect
	github.com/quic-go/quic-go v0.38.1 // indirect
	github.com/quic-go/webtransport-go v0.5.3 // indirect
	go.uber.org/mock v0.4.0 // indirect
	golang.org/x/crypto v0.22.0 // indirect
	golang.org/x/exp v0.0.0-20240416160154-fe59bbe5cc7f // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/net v0.24.0 // indirect
	golang.org/x/sys v0.19.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.20.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)
