package main

import (
	"fmt"
	"net"
	"strings"
)

var ips = make(map[string][]string)

func main() {

	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	for _, iface := range ifaces {
		if iface.Name == "lo" {
			continue
		}
		var listaddr []string
		addrs, err := iface.Addrs()
		if err != nil {
			panic(err)
		}

		for _, addr := range addrs {
			if IsIPv6(addr.String()) {
				continue
			}
			listaddr = append(listaddr, addr.String())
		}
		ips[iface.Name] = listaddr
	}
	for k, v := range ips {
		fmt.Println(k, v)
	}
}

func IsIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}
