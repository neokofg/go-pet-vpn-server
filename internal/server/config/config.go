package config

import "net"

type Config struct {
	TCPAddr      string
	UDPAddr      string
	DatabasePath string
	Network      *net.IPNet
}
