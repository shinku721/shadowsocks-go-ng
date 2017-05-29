package shadowsocks

import (
	"errors"
	"io"
)

var SERVER_NOT_EXIST = errors.New("Server does not exist")
var UNIMPLEMENTED = errors.New("unimplemented")

type ServerManager struct {
	host    string
	servers map[uint16]*ServerContext
}

func NewServerManager(host string) ServerManager {
	return ServerManager{
		host:    host,
		servers: make(map[uint16]*ServerContext),
	}
}

func (m *ServerManager) Add(port uint16, keyDeriver io.Reader, method string, timeout int) (err error) {
	var ctx ServerContext
	ctx, err = NewServerContext(m.host, port, keyDeriver, method, timeout)
	if err != nil {
		return
	}
	go ctx.Run()
	m.servers[port] = &ctx
	return
}

func (m *ServerManager) Remove(port uint16) (err error) {
	ctx, ok := m.servers[port]
	if !ok {
		return SERVER_NOT_EXIST
	}
	ctx.Stop() // ignoring errors
	delete(m.servers, port)
	return
}

func (m *ServerManager) Listen(addr string) (err error) {
	return UNIMPLEMENTED
}
