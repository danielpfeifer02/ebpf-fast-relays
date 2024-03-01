package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	spec, err := ebpf.LoadCollectionSpec("ingress.o")
	if err != nil {
		panic(err)
	}

	prog := spec.Programs["ingress_exec"]
	if prog == nil {
		panic("No program named 'ingress_exec' found in collection")
	}

	iface := os.Getenv("INTERFACE")
	iface = "lo" // TODO remove
	if iface == "" {
		panic("No interface specified. Please set the INTERFACE environment variable to the name of the interface to be used")
	}
	ifaceIdx, err := net.InterfaceByName(iface)
	if err != nil {
		panic(fmt.Sprintf("Failed to get interface %s: %v\n", iface, err))
	}

	opts := link.XDPOptions{
		Program:   prog,
		Interface: ifaceIdx.Index,
	}

	lnk, err := link.AttachXDP(opts)
	if err != nil {
		panic(err)
	}
	defer lnk.Close()

	// Open the eBPF map created for storing printk output
	mapFDs := spec.GetMap("bpf_output")
	if mapFDs == nil {
		panic("No map named 'bpf_output' found in collection")
	}

	// Create a map for reading eBPF map
	bpfMap := ebpf.NewMap(mapFDs)

	// Wait for Ctrl+C to exit the program
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGTERM)

	fmt.Println("Successfully loaded and attached BPF program.")

	go func() {
		for {
			// Read from the eBPF map
			key, val, next := bpfMap.GetNext(nil)
			for next {
				fmt.Printf("bpf_printk: %s\n", val)
				key, val, next = bpfMap.GetNext(key)
			}
		}
	}()

	<-exit
}
