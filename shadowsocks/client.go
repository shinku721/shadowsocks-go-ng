package shadowsocks

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

var v4InV6Prefix = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}

// ClientContext represents an instance of client. It listens on a
// local port, and is configured to connect certain server address
// using specified encryption.
// It accepts several protocols, e.g. HTTP proxy, socks4(a), socks5.
// The combinition should be able to be configured in the future.
type ClientContext struct {
	listener              net.Listener
	running               chan bool
	serverAddr            string
	cipherFactory         CipherFactory
	err                   chan error
	timeout               time.Duration
	httpConnectionManager *HTTPConnectionManager
}

// NewClientContext creates a new client context.
func NewClientContext(addr string, port uint16, local_addr string, local_port uint16, keyDeriver io.Reader, method string, timeout int) (ctx ClientContext, err error) {
	if IsIPv6(local_addr) {
		local_addr = "[" + local_addr + "]"
	}
	cipherInfo, ok := Ciphers[method]
	if !ok {
		err = fmt.Errorf("Unknown cipher: %s", method)
		return
	}
	key := make([]byte, cipherInfo.keySize)
	var n int
	n, err = keyDeriver.Read(key)
	if err != nil {
		return
	}
	if n < cipherInfo.keySize {
		err = fmt.Errorf("Insufficient key size")
		return
	}
	if IsIPv6(addr) {
		addr = "[" + addr + "]"
	}
	serverAddr := addr + ":" + strconv.Itoa(int(port))
	var server net.Listener
	server, err = net.Listen("tcp", local_addr+":"+strconv.Itoa(int(local_port)))
	if err != nil {
		return
	}
	ctx = ClientContext{
		listener:      server,
		running:       make(chan bool, 1),
		serverAddr:    serverAddr,
		cipherFactory: cipherInfo.newFactory(key),
		err:           make(chan error, 1),
		timeout:       time.Duration(timeout) * time.Second,
	}
	ctx.running <- false
	return
}

// Run runs a client. Usually this should be run in a goroutine.
func (ctx *ClientContext) Run() {
	running := <-ctx.running
	ctx.running <- true
	if running {
		log.Print("Client is already running")
		return
	}
	// clear error
	select {
	case <-ctx.err:
	default:
	}
	ctx.httpConnectionManager = NewHTTPConnectionManager(ctx)
	for {
		FDAttain()
		conn, err := ctx.listener.Accept()
		if err != nil {
			FDRelease()
			ctx.httpConnectionManager.Delete()
			running = <-ctx.running
			ctx.running <- false
			if !running {
				log.Panic("Client is running, but status is false")
			}
			if strings.Index(err.Error(), "use of closed network connection") != -1 {
				ctx.err <- nil
			} else {
				ctx.err <- err
			}
			return
		}
		go ctx.HandleConnection(conn)
	}
}

// Stop stops the client running goroutine.
func (ctx *ClientContext) Stop() {
	running := <-ctx.running
	ctx.running <- running
	if !running {
		return
	}
	ctx.listener.Close()
}

// Wait waits the client to stop and return its error
func (ctx *ClientContext) Wait() (err error) {
	return <-ctx.err
}

// HandleConnection handles client connections, checking
// input buffer, and dispatch connections to different
// protocol handler.
func (ctx *ClientContext) HandleConnection(conn net.Conn) {
	defer FDRelease()
	var err error
	defer conn.Close()
	defer func() {
		if err != nil {
			log.Print(err)
		}
	}()
	tconn := PlainConn{conn.(*net.TCPConn)}
	tconn.TCPConn.SetNoDelay(true)
	tconn.TCPConn.SetKeepAlivePeriod(ctx.timeout)
	tconn.TCPConn.SetKeepAlive(true)

	buf := NewBuffer()
	if DetectRedir(tconn) {
		err = ctx.HandleRedir(tconn, buf)
	} else {
		for {
			err = tconn.SSRead(buf)
			if err != nil {
				return
			}
			if DetectSocks5(buf) {
				err = ctx.HandleSocks5(tconn, buf)
			} else if DetectSocks4(buf) {
				err = ctx.HandleSocks4(tconn, buf)
			} else if DetectHTTP(buf) {
				err = ctx.HandleHTTP(tconn, buf)
			} else {
				continue
			}
			break
		}
	}
}

type ConnectInfo interface {
	String() string
	SSLen() int
	SSBuf([]byte)
}

type IPInfo struct {
	ip   net.IP
	port uint16
}

func (me *IPInfo) String() string {
	s := me.ip.String()
	if IsIPv6(s) {
		return "[" + s + "]:" + strconv.Itoa(int(me.port))
	} else {
		return s + ":" + strconv.Itoa(int(me.port))
	}
}

func (me *IPInfo) SSLen() int {
	if bytes.Equal(me.ip[:12], v4InV6Prefix) {
		return 1 + 4 + 2
	} else {
		return 1 + 16 + 2
	}
}

func (me *IPInfo) SSBuf(p []byte) {
	if bytes.Equal(me.ip[:12], v4InV6Prefix) {
		p[0] = 0x01
		copy(p[1:5], me.ip[12:])
		binary.Write(bytes.NewBuffer(p[:5]), binary.BigEndian, &me.port)
	} else {
		p[0] = 0x04
		copy(p[1:17], me.ip[:])
		binary.Write(bytes.NewBuffer(p[:17]), binary.BigEndian, &me.port)
	}
}

type HostInfo struct {
	host string
	port uint16
}

func (me *HostInfo) String() string {
	return me.host + ":" + strconv.Itoa(int(me.port))
}

func (me *HostInfo) SSLen() int {
	return 1 + 1 + len(me.host) + 2
}

func (me *HostInfo) SSBuf(p []byte) {
	l := len(me.host)
	p[0] = 0x03
	p[1] = byte(l)
	copy(p[2:], []byte(me.host))
	binary.Write(bytes.NewBuffer(p[:2+l]), binary.BigEndian, &me.port)
}
