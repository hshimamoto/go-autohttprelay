// go-autohttprelay
//
// MIT License Copyright(c) 2020 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
package autohttprelay

import (
    "fmt"
    "net"
    "strings"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/vishvananda/netlink"
    "github.com/hshimamoto/go-iorelay"
    "github.com/hshimamoto/go-session"
)

type RelayIP struct {
    IP net.IP
    Last time.Time
}

func (rip *RelayIP)String() string {
    return rip.IP.String()
}

type RelayServer struct {
    Serv *session.Server
    Proxy string
    Addr string
    IP *RelayIP
    Port layers.TCPPort
    Last time.Time
}

func NewRelayServer(proxy string, ip *RelayIP, port layers.TCPPort) (*RelayServer, error) {
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
	rs.IP.Last = time.Now()
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
    // remove first
    link, err := netlink.LinkByName(name)
    if err == nil {
	err = netlink.LinkDel(link)
	if err != nil {
	    return nil, err
	}
    }

    // add dummy device anyway
    dmy := &netlink.Dummy{}
    dmy.Name = name
    netlink.LinkAdd(dmy)
    netlink.LinkSetUp(dmy)

    // check it
    link, err = netlink.LinkByName(name)
    if err != nil {
	return nil, err
    }

    return link, nil
}

type AutoRelayManager struct {
    servers []*RelayServer
    ips []*RelayIP
    pipe chan SYNPacket
    handler func(SYNPacket)
    inf string
    proxy string
    proxyip string
}

func defAutoRelayHandler(syn SYNPacket) {
}

func NewAutoRelayManager(inf, proxy string) (*AutoRelayManager, error) {
    manager := &AutoRelayManager{}
    manager.servers = []*RelayServer{}
    manager.ips = []*RelayIP{}
    manager.pipe = make(chan SYNPacket)
    manager.handler = defAutoRelayHandler
    manager.inf = inf;
    manager.proxy = proxy
    a := strings.Split(proxy, ":")
    manager.proxyip = a[0]
    return manager, nil
}

func (manager *AutoRelayManager)SetHandler(handler func(SYNPacket)) {
    manager.handler = handler
}

func (manager *AutoRelayManager)Prepare() error {
    if err := StartSYNCapture(manager.inf, manager.pipe); err != nil {
	return err
    }
    if err := StartSYNCapture("lo", manager.pipe); err != nil {
	return err
    }
    return nil
}

func (manager *AutoRelayManager)Run() {
    for syn := range manager.pipe {
	if syn.IP.String() == manager.proxyip {
	    continue
	}
	manager.handler(syn)
    }
}

func (manager *AutoRelayManager)AddServer(ip net.IP, port layers.TCPPort) {
    addr := fmt.Sprintf("%s:%d", ip, port)
    for _, server := range manager.servers {
	if server.Addr == addr {
	    return
	}
    }
    rip := &RelayIP{ IP: ip, Last: time.Now() }
    server, err := NewRelayServer(manager.proxy, rip, port)
    if err != nil {
	return
    }
    manager.servers = append(manager.servers, server)
    go server.Run()
}
