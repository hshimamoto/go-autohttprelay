// go-autohttprelay / cmd / autohttprelay
//
// MIT License Copyright(c) 2020 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
package main

import (
    "fmt"
    "os"

    "github.com/hshimamoto/go-autohttprelay"
)

func main() {
    if len(os.Args) < 3 {
	fmt.Println("pass inf proxy")
	return
    }
    name := os.Args[1]
    proxy := os.Args[2]

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
