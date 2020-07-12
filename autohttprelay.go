// go-autohttprelay
//
// MIT License Copyright(c) 2020 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
package autohttprelay

import (
    "fmt"
    "net"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/vishvananda/netlink"
    "github.com/hshimamoto/go-iorelay"
    "github.com/hshimamoto/go-session"
)

type RelayServer struct {
    Serv *session.Server
    Proxy string
    Addr string
    IP net.IP
    Port layers.TCPPort
    Last time.Time
}

func NewRelayServer(proxy string, ip net.IP, port layers.TCPPort) (*RelayServer, error) {
    addr := fmt.Sprintf("%s:%d", ip, port)
    rs := &RelayServer{
	Proxy: proxy,
	Addr: addr,
	IP: ip,
	Port: port,
	Last: time.Now(),
    }
    serv, err := session.NewServer(addr, func(conn net.Conn) {
	rs.Last = time.Now()
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
    rs.Serv = serv
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
    filter := "dst net not 127.0.0.0/8"
    filter += " and dst net not 10.0.0.0/8"
    filter += " and dst net not 172.16.0.0/12"
    filter += " and dst net not 192.168.0.0/16"
    filter += " and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"
    err = handle.SetBPFFilter(filter)
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

func NewDummyDevice(name string) (netlink.Link, error) {
    dmy := &netlink.Dummy{}
    dmy.Name = name
    // add dummy device anyway
    netlink.LinkAdd(dmy)
    netlink.LinkSetUp(dmy)

    // check it
    link, err := netlink.LinkByName(name)
    if err != nil {
	return nil, err
    }

    return link, nil
}

type AutoRelayManager struct {
    servers []*RelayServer
    pipe chan SYNPacket
    handler func(SYNPacket)
}

func NewAutoRelayManager(inf string, handler func(SYNPacket)) (*AutoRelayManager, error) {
    manager := &AutoRelayManager{}
    manager.servers = []*RelayServer{}
    manager.pipe = make(chan SYNPacket)
    manager.handler = handler
    if err := StartSYNCapture(inf, manager.pipe); err != nil {
	return nil, err
    }
    if err := StartSYNCapture("lo", manager.pipe); err != nil {
	return nil, err
    }
    return manager, nil
}

func (manager *AutoRelayManager)Run() {
    for syn := range manager.pipe {
	manager.handler(syn)
    }
}
