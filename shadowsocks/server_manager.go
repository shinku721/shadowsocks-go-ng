package shadowsocks

import (
	"encoding/json"
	"log"
	"net"
	"strings"
)

type ServerManager struct {
	servers map[string]*ServerContext
	manager net.PacketConn
	res     chan error
}

func NewServerManager() ServerManager {
	return ServerManager{
		servers: make(map[string]*ServerContext),
		manager: nil,
		res:     make(chan error, 1),
	}
}

func (m *ServerManager) Add(config Config) (err error) {
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
		<-m.res
		if !unixsock {
			m.manager, err = net.ListenPacket("udp", addr)
		} else {
			m.manager, err = net.Listen("unixpacket", addr)
		}
		if err != nil {
			m.manager = nil
		} else {
			go m.RunManager()
		}
	}
	return
}

func (m *ServerManager) RunManager() {
	var err error
	defer func() {
		m.manager.Close()
		m.res <- err
	}()
	b := make([]byte, 4096)
	for {
		var n int
		var addr net.Addr
		n, addr, err = m.manager.ReadFrom(b)
		if err != nil {
			return
		}
		req := b[:n]
		var cmd string
		var data []byte
		i := strings.Index(req, ":")
		if i == -1 {
			cmd = string(req)
		} else {
			cmd := string(req[:i])
			data := req[i+1:]
		}
		var res string
		if cmd == "ping" {
			res = "pong"
		} else if cmd == "add" {
			var v map[string]interface{}
			if json.Unmarshal(data, &v) != nil {
				// todo: handle error
			}
			// todo
		} else if cmd == "remove" {
			var v map[string]int
			if json.Unmarshal(data, &v) != nil {
				// todo: handle error
			}
			// todo
		}
		_, err = m.manager.WriteTo([]byte(res), addr)
		if err != nil {
			return
		}
	}
}
