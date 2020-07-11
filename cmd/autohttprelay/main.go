// go-autohttprelay / cmd / autohttprelay
//
// MIT License Copyright(c) 2020 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
package main

import (
    "fmt"
    "net"
    "os"
    "strings"

    "github.com/hshimamoto/go-autohttprelay"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/vishvananda/netlink"
)

func isGlobal(ip net.IP) bool {
    if ip[0] == 127 {
	return false
    }
    if ip[0] == 10 {
	return false
    }
    if ip[0] == 172 {
	if (16 <= ip[1]) && (ip[1] <= 31) {
	    return false
	}
	return true
    }
    if (ip[0] == 192) && (ip[1] == 168) {
	return false
    }
    if ip.String() == proxyip {
	return false
    }
    // TODO check multicast
    return true
}

func dummyIP(ip net.IP) {
    link, err := netlink.LinkByName(dummy)
    if err != nil {
	fmt.Println(err)
	return
    }
    addr, err := netlink.ParseAddr(ip.String() + "/32")
    if err != nil {
	fmt.Println(err)
	return
    }
    err = netlink.AddrAdd(link, addr)
    if err != nil {
	fmt.Println(err)
	return
    }
}

func initDummy() {
    dmy := &netlink.Dummy{}
    dmy.Name = dummy
    netlink.LinkAdd(dmy)
    netlink.LinkSetUp(dmy)

    link, err := netlink.LinkByName(dummy)
    if err != nil {
	fmt.Println(err)
	return
    }
    fmt.Println(link)

    addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
    if err != nil {
	fmt.Println(err)
	return
    }
    for _, a := range addrs {
	fmt.Println(a)
	if isGlobal(a.IP) == false {
	    continue
	}
	// remove ip
	netlink.AddrDel(link, &a)
    }
}

var fwds []*autohttprelay.RelayServer = []*autohttprelay.RelayServer{}

func addFwdServer(addr string) {
    fwd, err := autohttprelay.NewRelayServer(proxy, addr)
    if err != nil {
	fmt.Println(err)
	return
    }
    fwds = append(fwds, fwd)
    go fwd.Run()
}

func process(ip net.IP, port layers.TCPPort) {
    fmt.Printf(" launch %s:%s\n", ip, port)
    dummyIP(ip)
    addr := fmt.Sprintf("%s:%d", ip, port)
    for _, fwd := range fwds {
	if fwd.Addr == addr {
	    return
	}
    }
    addFwdServer(addr)
}

var dummy string
var proxy string
var proxyip string

func pcap_process(name string) {
    ifs, err := pcap.FindAllDevs()
    if err != nil {
	fmt.Println(err)
	return
    }
    ok := false
    for _, inf := range ifs {
	//fmt.Println(inf)
	if (inf.Name == name) {
	    ok = true
	    break
	}
    }
    if !ok {
	fmt.Println("no interface")
	return
    }

    handle, err := pcap.OpenLive(name, 256, false, pcap.BlockForever)
    if err != nil {
	fmt.Println(err)
	return
    }
    if err := handle.SetBPFFilter("tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"); err != nil {
	fmt.Println(err)
	return
    }
    source := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range source.Packets() {
	//fmt.Println(packet)
	ipv4l := packet.Layer(layers.LayerTypeIPv4)
	if ipv4l == nil {
	    continue
	}
	ipv4 := ipv4l.(*layers.IPv4)
	tcpl := packet.Layer(layers.LayerTypeTCP)
	if tcpl == nil {
	    continue
	}
	tcp := tcpl.(*layers.TCP)
	if isGlobal(ipv4.DstIP) {
	    fmt.Printf("%s:%s -> %s:%s\n", ipv4.SrcIP, tcp.SrcPort, ipv4.DstIP, tcp.DstPort)
	    process(ipv4.DstIP, tcp.DstPort)
	}
    }
}

func main() {
    if len(os.Args) < 3 {
	fmt.Println("pass inf proxy")
	return
    }
    name := os.Args[1]
    proxy = os.Args[2]
    a := strings.Split(proxy, ":")
    proxyip = a[0]

    dummy = "autohttprelay"
    initDummy()

    go pcap_process(name)
    pcap_process("lo")
}
