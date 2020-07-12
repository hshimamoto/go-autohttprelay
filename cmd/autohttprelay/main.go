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
    "github.com/vishvananda/netlink"
)

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
    _, err := autohttprelay.NewDummyDevice(dummy)
    if err != nil {
	fmt.Println(err)
	return
    }

    var manager *autohttprelay.AutoRelayManager

    manager, err = autohttprelay.NewAutoRelayManager(name, proxy, func(syn autohttprelay.SYNPacket) {
	fmt.Printf("->%s:%s\n", syn.IP, syn.Port)
	dummyIP(syn.IP)
	manager.AddServer(syn.IP, syn.Port)
    })
    if err != nil {
	fmt.Println(err)
	return
    }
    manager.Run()
}
