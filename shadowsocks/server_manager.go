package shadowsocks

type ServerManager struct {
	servers map[string]*ServerContext
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
	return ERR_UNIMPLEMENTED
}
