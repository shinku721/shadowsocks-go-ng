package shadowsocks

import (
	"io"
	"time"
)

type Config struct {
	// Server listening address
	ServerHost string
	// Server listening port
	ServerPort uint16
	// Local listening address (Client only)
	LocalHost string
	// Local listening port (Client only)
	LocalPort uint16
	// Encryption method
	Method string
	// Key generator
	KeyDeriver io.Reader
	// TCP keepalive timeout
	Timeout time.Duration
	// Connect IPv4 address only (Server only)
	ConnectV4Only bool
	// New connection timeout (Server only)
	ConnectTimeout time.Duration
}

func DefaultConfig() Config {
	return Config{
		ServerHost:     "::",
		ServerPort:     8388,
		LocalHost:      "127.0.0.1",
		LocalPort:      1080,
		Method:         "chacha20-ietf-poly1305",
		KeyDeriver:     nil,
		Timeout:        300 * time.Second,
		ConnectV4Only:  false,
		ConnectTimeout: 15 * time.Second,
	}
}
