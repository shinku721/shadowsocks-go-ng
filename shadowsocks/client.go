package shadowsocks

import (
	"fmt"
	"io"
	"log"
	"net"
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

type ClientConfig struct {
	ServerHost string
	ServerPort uint16
	LocalHost  string
	LocalPort  uint16
	Method     string
	KeyDeriver io.Reader
	Timeout    time.Duration
}

func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		ServerHost: "127.0.0.1",
		ServerPort: 8388,
		LocalHost:  "127.0.0.1",
		LocalPort:  1080,
		Method:     "chacha20-ietf-poly1305",
		KeyDeriver: nil,
		Timeout:    300 * time.Second,
	}
}

// NewClientContext creates a new client context.
func NewClientContext(config ClientConfig) (ctx ClientContext, err error) {
	cipherInfo, ok := Ciphers[config.Method]
	if !ok {
		err = fmt.Errorf("Unknown cipher: %s", config.Method)
		return
	}
	key := make([]byte, cipherInfo.keySize)
	var n int
	n, err = config.KeyDeriver.Read(key)
	if err != nil {
		return
	}
	if n < cipherInfo.keySize {
		err = fmt.Errorf("Insufficient key size")
		return
	}
	var server net.Listener
	server, err = net.Listen("tcp", WrapAddr(config.LocalHost, config.LocalPort))
	if err != nil {
		return
	}
	ctx = ClientContext{
		listener:      server,
		running:       make(chan bool, 1),
		serverAddr:    WrapAddr(config.ServerHost, config.ServerPort),
		cipherFactory: cipherInfo.newFactory(key),
		err:           make(chan error, 1),
		timeout:       config.Timeout,
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

func (ctx *ClientContext) DialServer() (conn SSConn, err error) {
	var rconn net.Conn
	rconn, err = net.Dial("tcp", ctx.serverAddr)
	if err != nil {
		return
	}
	rconn.(*net.TCPConn).SetNoDelay(true)
	conn = ctx.cipherFactory.Wrap(PlainConn{rconn.(*net.TCPConn)})
	return
}