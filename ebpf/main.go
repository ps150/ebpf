// main.go
package main

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "log"
    "net"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/perf"
    "github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf traffic_capture.c

func main() {
    // Load pre-compiled programs
    objs := bpfObjects{}
    if err := loadBpfObjects(&objs, nil); err != nil {
        log.Fatalf("loading objects: %v", err)
    }
    defer objs.Close()

    // Attach the program to the default interface
    iface, err := net.InterfaceByName("eth0")
    if err != nil {
        log.Fatalf("getting interface: %v", err)
    }

    l, err := link.AttachXDP(link.XDPOptions{
        Program:   objs.CaptureTraffic,
        Interface: iface.Index,
    })
    if err != nil {
        log.Fatalf("attaching XDP: %v", err)
    }
    defer l.Close()

    // Open a perf event reader
    rd, err := perf.NewReader(objs.Events, 4096)
    if err != nil {
        log.Fatalf("creating perf event reader: %v", err)
    }
    defer rd.Close()

    fmt.Println("Listening for events...")

    for {
        record, err := rd.Read()
        if err != nil {
            log.Fatalf("reading perf event: %v", err)
        }

        if record.LostSamples != 0 {
            log.Printf("lost %d samples", record.LostSamples)
            continue
        }

        var iphdr struct {
            VersionIHL     uint8
            TOS            uint8
            TotalLength    uint16
            ID             uint16
            FlagsFragment  uint16
            TTL            uint8
            Protocol       uint8
            HeaderChecksum uint16
            SrcAddr        [4]byte
            DstAddr        [4]byte
        }

        if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &iphdr); err != nil {
            log.Printf("parsing IP header: %v", err)
            continue
        }

        fmt.Printf("Captured packet: src=%v, dst=%v, protocol=%d\n",
            net.IP(iphdr.SrcAddr[:]),
            net.IP(iphdr.DstAddr[:]),
            iphdr.Protocol)
    }
}