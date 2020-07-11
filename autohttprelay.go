// go-autohttprelay
//
// MIT License Copyright(c) 2020 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
package autohttprelay

import (
    "net"

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
