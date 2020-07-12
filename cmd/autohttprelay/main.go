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
    "github.com/google/gopacket/layers"
    "github.com/vishvananda/netlink"
)

func isGlobal(ip net.IP) bool {
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
    link, err := autohttprelay.NewDummyDevice(dummy)
    if err != nil {
	fmt.Println(err)
	return
    }

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

func process(ip net.IP, port layers.TCPPort) {
    addr := fmt.Sprintf("%s:%d", ip, port)
    for _, fwd := range fwds {
	if fwd.Addr == addr {
	    return
	}
    }
    fmt.Printf(" launch %s:%s\n", ip, port)
    dummyIP(ip)
    fwd, err := autohttprelay.NewRelayServer(proxy, ip, port)
    if err != nil {
	fmt.Println(err)
	return
    }
    fwds = append(fwds, fwd)
    go fwd.Run()
}

var dummy string
var proxy string
var proxyip string

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

    pipe := make(chan autohttprelay.SYNPacket)

    err := autohttprelay.StartSYNCapture(name, pipe)
    if err != nil {
	fmt.Println(err)
    }
    err = autohttprelay.StartSYNCapture("lo", pipe)
    if err != nil {
	fmt.Println(err)
    }

    for syn := range pipe {
	fmt.Printf("-> %s:%s\n", syn.IP, syn.Port)
	if isGlobal(syn.IP) {
	    process(syn.IP, syn.Port)
	}
    }
}
