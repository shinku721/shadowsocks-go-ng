package shadowsocks

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

type HTTPConnCtx struct {
	conn SSConn
	addr string
}

type HTTPConnectionManager struct {
	connections map[string][]*HTTPConnCtx
	watchers    map[*HTTPConnCtx]chan bool
	ctx         *ClientContext
	req         chan string
	res         chan *HTTPConnCtx
	err         chan error
	store       chan *HTTPConnCtx
	kill        chan *HTTPConnCtx
	alive       chan bool
	done        chan bool
}

func NewHTTPConnectionManager(ctx *ClientContext) (m *HTTPConnectionManager) {
	m = &HTTPConnectionManager{
		connections: map[string][]*HTTPConnCtx{},
		watchers:    map[*HTTPConnCtx]chan bool{},
		ctx:         ctx,
		req:         make(chan string),
		res:         make(chan *HTTPConnCtx),
		err:         make(chan error),
		store:       make(chan *HTTPConnCtx),
		kill:        make(chan *HTTPConnCtx),
		alive:       make(chan bool, 1),
		done:        make(chan bool),
	}
	m.alive <- true
	go m.run()
	return
}

func (m *HTTPConnectionManager) Get(addr string) (hctx *HTTPConnCtx, err error) {
	alive := <-m.alive
	defer func() { m.alive <- alive }()
	if !alive {
		return nil, ERR_HTTP_MANAGER_DEAD
	}
	for {
		m.req <- addr
		select {
		case err = <-m.err:
		case hctx = <-m.res:
		}
		if err != nil {
			return
		}
		if hctx.conn.Alive() {
			return
		} else {
			hctx.conn.Close()
		}
	}
}

func (m *HTTPConnectionManager) Release(hctx *HTTPConnCtx) {
	alive := <-m.alive
	defer func() { m.alive <- alive }()
	if hctx == nil {
		return
	}
	if !hctx.conn.Alive() {
		hctx.conn.Close()
		return
	}
	if !alive {
		hctx.conn.Close()
		return
	}
	m.store <- hctx
}

func (m *HTTPConnectionManager) Delete() {
	m.done <- false
}

func (m *HTTPConnectionManager) run() {
	var err error
	for {
		select {
		case addr := <-m.req:
			if len(m.connections[addr]) == 0 {
				pcol := strings.Index(addr, ":")
				var host string
				var port uint16
				if pcol != -1 {
					host = addr[:pcol]
					var pport int64
					pport, err = strconv.ParseInt(addr[pcol+1:], 10, 32)
					if err != nil {
						m.err <- err
						continue
					}
					port = uint16(pport)
				} else {
					host = addr
					port = 80
				}

				if len(host) > 255 {
					m.err <- ERR_HTTP_HOST_TOO_LONG
					continue
				}

				b := make([]byte, 2+len(host)+2)
				b[0] = 0x03
				b[1] = byte(len(host))
				copy(b[2:2+len(host)], []byte(host))
				binary.Write(bytes.NewBuffer(b[:2+len(host)]), binary.BigEndian, &port)

				var rconn net.Conn
				if rconn, err = net.Dial("tcp", m.ctx.serverAddr); err != nil {
					m.err <- err
					continue
				}
				trconn := PlainConn{rconn.(*net.TCPConn)}
				wtrconn := m.ctx.cipherFactory.Wrap(trconn)
				dwtrconn := NewDelayInitConn(wtrconn, b)
				m.res <- &HTTPConnCtx{
					conn: dwtrconn,
					addr: addr,
				}
			} else {
				ls := m.connections[addr]
				hctx := ls[len(ls)-1]
				ls[len(ls)-1] = nil
				m.connections[addr] = ls[:len(ls)-1]

				if m.watchers[hctx] != nil {
					m.watchers[hctx] <- true
					m.res <- hctx
					delete(m.watchers, hctx)
				} else {
					log.Panic("HTTPWatcher not found")
				}
			}
		case hctx := <-m.store:
			watcher := make(chan bool, 1)
			go m.watch(hctx, watcher)
			m.watchers[hctx] = watcher
			m.connections[hctx.addr] = append(m.connections[hctx.addr], hctx)
		case hctx := <-m.kill:
			ls := m.connections[hctx.addr]
			for k, v := range ls {
				if v == hctx {
					ls[k] = ls[len(ls)-1]
					ls[len(ls)-1] = nil
					m.connections[hctx.addr] = ls[:len(ls)-1]
					break
				}
			}
			delete(m.watchers, hctx)
			hctx.conn.Close()
		case done := <-m.done:
			if done {
				break
			} else {
				go func() {
					<-m.alive
					m.alive <- false
					m.done <- true
				}()
			}
		}
	}
	// do some cleanup here?
	for _, v := range m.connections {
		for _, hctx := range v {
			hctx.conn.Close()
			delete(m.watchers, hctx)
		}
	}
}

func (m *HTTPConnectionManager) watch(hctx *HTTPConnCtx, watcher chan bool) {
	select {
	case <-time.After(5 * time.Second):
		m.kill <- hctx
	case <-watcher:
	}
}
