package shadowsocks

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
)

/* DetectHTTP detects whether the buffer contains valid HTTP proxy request.
   Protocol definition: RFC 7230 5.3.2, RFC 7231 4.3.6
   https://www.ietf.org/rfc/rfc7230.txt
   https://www.ietf.org/rfc/rfc7231.txt
*/
func DetectHTTP(buf *SSBuffer) bool {
	headpos := 0
	for i := 0; i < len(buf.buf)-1; i++ {
		if buf.buf[i] == 0x0d && buf.buf[i+1] == 0x0a {
			headpos = i
			break
		}
	}
	if headpos == 0 {
		return false
	}
	headline := string(buf.buf[:headpos])
	if strings.HasSuffix(headline, "HTTP/1.0") || strings.HasSuffix(headline, "HTTP/1.1") {
		return true
	}
	return false
}

var returnEstablished = []byte("HTTP/1.1 200 Connection established\r\n\r\n")

// HandleHTTP handles a HTTP/1.0 or HTTP/1.1 proxy connection.
func (ctx *ClientContext) HandleHTTP(tconn SSConn, buf *SSBuffer) (err error) {
	var rhctx *HTTPConnCtx
	defer func() {
		if rhctx != nil {
			rhctx.conn.Close()
		}
	}()
	for {
		var header HTTPHeader
		header, err = HTTPParseHeader(tconn, buf, true)
		if err == io.EOF {
			ctx.httpConnectionManager.Release(rhctx)
			rhctx = nil
			err = nil
			return
		}
		if err != nil {
			HTTPWrite400(tconn)
			return
		}
		var method string
		if method, err = header.Method(); method == "CONNECT" { // tunnel
			var addr string
			if addr, err = header.URL(); err != nil {
				HTTPWrite400(tconn)
				return
			}
			var host string
			var port uint16
			if host, port, err = UnwrapAddr(addr); err != nil {
				HTTPWrite400(tconn)
				return ERR_HTTP_INVALID_HEADER
			}
			if len(host) > 255 {
				HTTPWrite400(tconn)
				return ERR_HTTP_HOST_TOO_LONG
			}

			rbuf := NewBuffer()
			rbuf.buf = rbuf.buf[:len(returnEstablished)]
			copy(rbuf.buf, returnEstablished)
			if err = tconn.SSWrite(rbuf); err != nil {
				return
			}

			buf.buf = buf.buf[:2+len(host)+2]
			buf.buf[0] = 0x03
			buf.buf[1] = byte(len(host))
			copy(buf.buf[2:2+len(host)], []byte(host))
			binary.Write(bytes.NewBuffer(buf.buf[:2+len(host)]), binary.BigEndian, &port)

			err = tconn.(PlainConn).SSReadTimeout(buf, 5)
			if err != nil {
				return
			}

			var wrconn SSConn
			wrconn, err = ctx.DialServer()
			if err != nil {
				return
			}
			defer wrconn.Close()

			res := make(chan error, 1)
			DPipe(tconn, wrconn, buf, rbuf, res)

			err = <-res
			return
		} else { // message forwarding
			var raddr string
			if raddr, err = header.URLHost(); err != nil {
				HTTPWrite400(tconn)
				return
			}
			if rhctx == nil || rhctx.addr != raddr || !rhctx.conn.Alive() {
				ctx.httpConnectionManager.Release(rhctx)
				rhctx, err = ctx.httpConnectionManager.Get(raddr)
				if err != nil {
					HTTPWrite502(tconn)
					return
				}
			}
			rconn := rhctx.conn

			clientKeepAlive := header.KeepAlive()
			//clientKeepAlive := false

			if header.headers["connection"] != nil {
				filter := strings.Split(header.headers["connection"].content, ",")
				for i := 0; i < len(filter); i++ {
					filter[i] = strings.ToLower(strings.Trim(filter[i], " "))
					delete(header.headers, filter[i])
				}
			}
			header.headers["host"] = &HTTPHeaderField{
				content: raddr,
				field:   "Host",
			}
			header.headers["connection"] = &HTTPHeaderField{
				content: "keep-alive",
				field:   "Connection",
			}
			delete(header.headers, "proxy-connection") // we will always keep-alive on server connections
			var rel string
			if rel, err = header.URLRel(); err != nil {
				return
			}
			if header.Version() == 1 {
				header.startline = method + " " + rel + " HTTP/1.1"
			} else {
				header.startline = method + " " + rel + " HTTP/1.0"
			}

			err = HTTPWriteHeader(rconn, header)
			if err != nil {
				HTTPWrite502(tconn)
				return
			}
			cerr := make(chan error, 1)
			go HTTPPipeBody(tconn, buf, rconn, header, cerr)

			rcerr := make(chan error, 1)
			go func() {
				var err error
				defer func() { rcerr <- err }()
				var rheader HTTPHeader
				rbuf := NewBuffer()
				var remoteKeepAlive bool
				for {
					rheader, err = HTTPParseHeader(rconn, rbuf, false)
					if err != nil {
						return
					}

					remoteKeepAlive = rheader.KeepAlive()
					if rheader.headers["connection"] != nil {
						filter := strings.Split(rheader.headers["connection"].content, ",")
						for i := 0; i < len(filter); i++ {
							filter[i] = strings.ToLower(strings.Trim(filter[i], " "))
							delete(rheader.headers, filter[i])
						}
					}
					if clientKeepAlive {
						rheader.headers["connection"] = &HTTPHeaderField{
							content: "keep-alive",
							field:   "Connection",
						}
					} else {
						rheader.headers["connection"] = &HTTPHeaderField{
							content: "close",
							field:   "Connection",
						}
					}
					err = HTTPWriteHeader(tconn, rheader)
					if err != nil {
						return
					}
					// continue pipe header if status is 100
					var st int
					if st, err = rheader.Status(); st != 100 {
						break
					}
				}

				trcerr := make(chan error, 1)
				HTTPPipeBody(rconn, rbuf, tconn, rheader, trcerr)
				err = <-trcerr
				if !remoteKeepAlive {
					rconn.Close()
				}
			}()

			select {
			case err = <-cerr:
				if err == nil {
					err = <-rcerr
				}
			case err = <-rcerr:
				if err == nil {
					err = <-cerr
				}
			}
			if err != nil {
				return
			}
			if !rconn.Alive() {
				return
			}

			if !clientKeepAlive {
				ctx.httpConnectionManager.Release(rhctx)
				rhctx = nil
				return
			}
		}
	}
}
