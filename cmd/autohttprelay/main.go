// go-autohttprelay / cmd / autohttprelay
//
// MIT License Copyright(c) 2020 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
package main

import (
    "fmt"
    "net"
    "os"

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

func main() {
    if len(os.Args) < 3 {
	fmt.Println("pass inf proxy")
	return
    }
    name := os.Args[1]
    proxy = os.Args[2]

    manager, err := autohttprelay.NewAutoRelayManager(name, proxy)
    if err != nil {
	fmt.Println(err)
	return
    }
    err = manager.Prepare()
    if err != nil {
	fmt.Println(err)
	return
    }
    manager.Run()
}
