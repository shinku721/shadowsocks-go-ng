package shadowsocks

import (
	"net"
	"strings"
)

type ServerManager struct {
	servers map[string]*ServerContext
	manager net.Listener
}

func NewServerManager() ServerManager {
	return ServerManager{
		servers: make(map[string]*ServerContext),
	}
}

func (m *ServerManager) Add(config ServerConfig) (err error) {
	key := WrapAddr(config.ServerHost, config.ServerPort)
	var ctx ServerContext
	ctx, err = NewServerContext(config)
	if err != nil {
		return
	}
	go ctx.Run()
	m.servers[key] = &ctx
	return
}

func (m *ServerManager) Remove(host string, port uint16) (err error) {
	key := WrapAddr(host, port)
	ctx, ok := m.servers[key]
	if !ok {
		return ERR_SERVER_NOT_EXIST
	}
	ctx.Stop() // ignoring errors
	delete(m.servers, key)
	return
}

func (m *ServerManager) Listen(addr string) (err error) {
	unixsock := true
	i := strings.Index(addr, "]:")
	if i != -1 {
		if addr[0] == '[' && IsIP(addr[1:i]) != 6 {
			unixsock = false
		}
	}
	i = strings.Index(addr, ":")
	if i != -1 {
		if IsIP(addr[:i]) == 4 {
			unixsock = false
		}
	}
	if m.manager != nil {
		m.manager.Close()
		if !unixsock {
			m.manager, err = net.Listen("udp", addr)
		} else {
			m.manager, err = net.Listen("unixpacket", addr)
		}
		if err != nil {
			m.manager = nil
		}
	}
	return
}
