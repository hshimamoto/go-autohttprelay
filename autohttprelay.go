// go-autohttprelay
//
// MIT License Copyright(c) 2020 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
package autohttprelay

import (
    "fmt"
    "net"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/hshimamoto/go-iorelay"
    "github.com/hshimamoto/go-session"
)

type RelayServer struct {
    Serv *session.Server
    Proxy string
    Addr string
}

func NewRelayServer(proxy, addr string) (*RelayServer, error) {
    serv, err := session.NewServer(addr, func(conn net.Conn) {
	defer conn.Close()
	pconn, err := session.Corkscrew(proxy, addr)
	if err != nil {
	    return
	}
	defer pconn.Close()
	iorelay.Relay(conn, pconn)
    })
    if err != nil {
	return nil, err
    }
    rs := &RelayServer{
	Serv: serv,
	Proxy: proxy,
	Addr: addr,
    }
    return rs, nil
}

func (rs *RelayServer)Run() {
    rs.Serv.Run()
}

type SYNPacket struct {
    IP net.IP
    Port layers.TCPPort
}

func StartSYNCapture(name string, pipe chan SYNPacket) error {
    ifs, err := pcap.FindAllDevs()
    if err != nil {
	return err
    }
    ok := false
    for _, i := range ifs {
	if (i.Name == name) {
	    ok = true
	    break
	}
    }
    if !ok {
	return fmt.Errorf("SetSYNCapture: no device %s", name)
    }
    handle, err := pcap.OpenLive(name, 256, false, pcap.BlockForever)
    if err != nil {
	return err
    }
    err = handle.SetBPFFilter("tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn")
    if err != nil {
	return err
    }
    source := gopacket.NewPacketSource(handle, handle.LinkType())
    // start back ground goroutine
    go func() {
	for packet := range source.Packets() {
	    ipv4l := packet.Layer(layers.LayerTypeIPv4)
	    if ipv4l == nil {
		continue
	    }
	    tcpl := packet.Layer(layers.LayerTypeTCP)
	    if tcpl == nil {
		continue
	    }
	    ipv4 := ipv4l.(*layers.IPv4)
	    tcp := tcpl.(*layers.TCP)
	    pipe <- SYNPacket{
		IP: ipv4.DstIP,
		Port: tcp.DstPort,
	    }
	}
    }()
    return nil
}
