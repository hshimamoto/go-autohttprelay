// go-autohttprelay
//
// MIT License Copyright(c) 2020, 2021 Hiroshi Shimamoto
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
    Addr string
    IP net.IP
    Port layers.TCPPort
    Last time.Time
    Connecter func(string) (net.Conn, error)
}

func NewRelayServer(ip net.IP, port layers.TCPPort, connecter func(string) (net.Conn, error)) (*RelayServer, error) {
    addr := fmt.Sprintf("%s:%d", ip, port)
    rs := &RelayServer{
	Addr: addr,
	IP: ip,
	Port: port,
	Last: time.Now(),
	Connecter: connecter,
    }
    serv, err := session.NewServer(addr, func(conn net.Conn) {
	rs.Last = time.Now()
	defer conn.Close()
	pconn, err := rs.Connecter(addr)
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
    connecter func(string) (net.Conn, error)
    inf string
    proxy string
    proxyip string
    dummy string
    link netlink.Link
}

func NewAutoRelayManager(inf, proxy string) (*AutoRelayManager, error) {
    manager := &AutoRelayManager{}
    manager.servers = []*RelayServer{}
    manager.ips = []*RelayIP{}
    manager.pipe = make(chan SYNPacket)
    manager.handler = manager.defAutoRelayHandler
    manager.connecter = manager.defAutoRelayConnecter
    manager.inf = inf;
    manager.proxy = proxy
    manager.dummy = "autohttprelay"
    a := strings.Split(proxy, ":")
    ip := net.ParseIP(a[0])
    if ip == nil {
	ips, err := net.LookupIP(a[0])
	if err == nil {
	    ip = ips[0]
	}
    }
    manager.proxyip = ip.String()
    return manager, nil
}

func (manager *AutoRelayManager)defAutoRelayHandler(syn SYNPacket) {
    // launch server
    manager.AddServer(syn.IP, syn.Port)
}

func (manager *AutoRelayManager)SetHandler(handler func(SYNPacket)) {
    manager.handler = handler
}

func (manager *AutoRelayManager)defAutoRelayConnecter(addr string) (net.Conn, error) {
    // use proxy
    return session.Corkscrew(manager.proxy, addr)
}

func (manager *AutoRelayManager)SetAutoRelayConnecter(connecter func(string)(net.Conn, error)) {
    manager.connecter = connecter
}

func (manager *AutoRelayManager)Prepare() error {
    link, err := NewDummyDevice(manager.dummy)
    if err != nil {
	return err
    }
    manager.link = link
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
	synip := syn.IP.String()
	if synip == manager.proxyip {
	    continue
	}
	// check dummy IP list
	found := false
	for _, ip := range manager.ips {
	    if ip.IP.String() == synip {
		found = true
		// touch
		ip.Last = time.Now()
		break
	    }
	}
	if found == false {
	    // add dummy IP
	    addr, _ := netlink.ParseAddr(synip + "/32")
	    netlink.AddrAdd(manager.link, addr)
	    manager.ips = append(manager.ips, &RelayIP{ IP: syn.IP, Last: time.Now() })
	}
	manager.handler(syn)
	// check dummy IP expired
	oneday := time.Now().Add(-24 * time.Hour)
	ips := []*RelayIP{}
	for _, ip := range manager.ips {
	    if ip.Last.Before(oneday) {
		addr, _ := netlink.ParseAddr(ip.IP.String() + "/32")
		err := netlink.AddrDel(manager.link, addr)
		if err != nil {
		    fmt.Println(err)
		}
		continue
	    }
	    ips = append(ips, ip)
	}
	manager.ips = ips
    }
}

func (manager *AutoRelayManager)AddServer(ip net.IP, port layers.TCPPort) {
    addr := fmt.Sprintf("%s:%d", ip, port)
    for _, server := range manager.servers {
	if server.Addr == addr {
	    return
	}
    }
    server, err := NewRelayServer(ip, port, manager.connecter)
    if err != nil {
	return
    }
    manager.servers = append(manager.servers, server)
    go server.Run()
}
