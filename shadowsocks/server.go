package shadowsocks

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// ServerContext represents an instance of Shadowsocks server
// which listens on a single port and accept a single kind of
// encryption.
type ServerContext struct {
	server         net.Listener
	running        chan bool
	err            chan error
	cipherFactory  CipherFactory
	connectV4Only  bool
	connectTimeout time.Duration
	timeout        time.Duration
}

// NewServerContext creates a new instance of ServerContext
// with specified arguments.
func NewServerContext(config Config) (ctx ServerContext, err error) {
	var server net.Listener
	server, err = net.Listen("tcp", WrapAddr(config.ServerHost, config.ServerPort))
	if err != nil {
		return
	}
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
	ctx = ServerContext{
		server:         server,
		running:        make(chan bool, 1),
		cipherFactory:  cipherInfo.newFactory(key),
		connectV4Only:  config.ConnectV4Only,
		err:            make(chan error, 1),
		connectTimeout: config.ConnectTimeout,
		timeout:        config.Timeout,
	}
	ctx.running <- false
	return
}

// Run runs the server, normally running in
// a new goroutine.
func (ctx *ServerContext) Run() {
	running := <-ctx.running
	ctx.running <- true
	if running { // server already running
		log.Printf("Server is already running")
		return
	}
	// clear error
	select {
	case <-ctx.err:
	default:
	}
	for {
		FDAttain()
		conn, err := ctx.server.Accept()
		if err != nil {
			FDRelease()
			running = <-ctx.running
			ctx.running <- false
			if !running {
				log.Panic("Server is running, but status is false")
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

// Stop stops the running server.
func (ctx *ServerContext) Stop() {
	running := <-ctx.running
	ctx.running <- running
	if !running {
		return
	}
	ctx.server.Close()
}

// Wait waits the server to stop and return its error.
func (ctx *ServerContext) Wait() (err error) {
	return <-ctx.err
}

// HandleConnection handles a newly accepted
// connection with configured ciphers.
func (ctx *ServerContext) HandleConnection(conn net.Conn) {
	defer FDRelease()
	var err error
	defer func() {
		if err != nil {
			log.Print(err.Error() + "(" + conn.(*net.TCPConn).RemoteAddr().String() + ")")
		}
		if !IsAuthError(err) {
			conn.Close()
		} else {
			// drain all data but keep the connection
			go func(conn net.Conn) {
				defer conn.Close()
				devnull := make([]byte, DEFAULT_BUF_SIZE)
				var err error = nil
				for err == nil {
					_, err = conn.Read(devnull)
				}
			}(conn)
		}
	}()
	tconn := PlainConn{conn.(*net.TCPConn)}
	tconn.TCPConn.SetNoDelay(true)
	tconn.TCPConn.SetKeepAlivePeriod(ctx.timeout)
	tconn.TCPConn.SetKeepAlive(true)
	wconn := ctx.cipherFactory.Wrap(tconn)

	buf := NewBuffer()
	var addr string
	var ln int
	for {
		err = wconn.SSRead(buf)
		if err != nil {
			return
		}
		addr, ln, err = ParseAddress(buf.buf)
		if err != nil {
			return
		}
		if len(buf.buf) >= ln {
			break
		}
	}
	copy(buf.buf[:], buf.buf[ln:])
	buf.buf = buf.buf[:len(buf.buf)-ln]

	var netType string
	if ctx.connectV4Only {
		netType = "tcp4"
	} else {
		netType = "tcp"
	}
	var rconn net.Conn
	rconn, err = net.DialTimeout(netType, addr, ctx.connectTimeout)
	if err != nil {
		return
	}
	defer rconn.Close()
	trconn := PlainConn{rconn.(*net.TCPConn)}
	trconn.TCPConn.SetNoDelay(true)

	rbuf := NewBuffer()
	res := make(chan error, 1)
	DPipe(wconn, trconn, buf, rbuf, res)

	err = <-res
}
