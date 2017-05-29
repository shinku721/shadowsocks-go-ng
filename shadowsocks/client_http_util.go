package shadowsocks

import (
	"io"
	"log"
	"strconv"
	"strings"
)

const HTTP_CONTENT_EOF = -1
const HTTP_CONTENT_CHUNKED = -2

func HTTPReadLine(tconn SSConn, buf *SSBuffer, i_offset int) (line string, offset int, err error) {
	offset = i_offset
	for i := offset; ; i++ {
		for i+1 >= len(buf.buf) {
			if err = tconn.SSRead(buf); err != nil {
				return
			}
		}
		if buf.buf[i] == 0x0d && buf.buf[i+1] == 0x0a {
			line = string(buf.buf[offset:i])
			offset = i + 2
			return
		}
	}
}

type HTTPHeader struct {
	req        bool
	startline  string
	headers    map[string]*HTTPHeaderField
	setCookies []*HTTPHeaderField
}
type HTTPHeaderField struct {
	content string
	field   string
}

func HTTPParseHeader(tconn SSConn, buf *SSBuffer, req bool) (header HTTPHeader, err error) {
	// parse in header
	header.req = req
	header.headers = map[string]*HTTPHeaderField{}
	offset := 0
	header.startline, offset, err = HTTPReadLine(tconn, buf, offset)
	// Should we skip empty lines here?
	if err != nil {
		return
	}
	// Note: We don't consider obs-fold
	var line string
	for {
		line, offset, err = HTTPReadLine(tconn, buf, offset)
		if err != nil {
			return
		}
		if line == "" {
			break
		}
		pcolon := strings.Index(line, ":")
		if pcolon == -1 {
			err = HTTP_INVALID_HEADER
			return
		}
		field := line[:pcolon]
		lfield := strings.ToLower(field)
		content := strings.Trim(line[pcolon+1:], " ")
		if header.headers[lfield] != nil {
			if lfield == "content-length" {
				if content != header.headers[lfield].content {
					err = HTTP_INVALID_HEADER
					return
				}
			} else {
				header.headers[lfield].content += ", " + content
			}
		} else {
			if lfield == "set-cookie" {
				header.setCookies = append(header.setCookies, &HTTPHeaderField{
					content: content,
					field:   field,
				})
			} else {
				header.headers[lfield] = &HTTPHeaderField{
					content: content,
					field:   field,
				}
			}
		}
	}
	// eat buffer
	copy(buf.buf, buf.buf[offset:])
	buf.buf = buf.buf[:len(buf.buf)-offset]
	return
}

func (header *HTTPHeader) Version() int {
	if header.req {
		if strings.HasSuffix(header.startline, "HTTP/1.1") {
			return 1
		} else if strings.HasSuffix(header.startline, "HTTP/1.0") {
			return 0
		} else {
			return -1
		}
	} else {
		if strings.HasPrefix(header.startline, "HTTP/1.1") {
			return 1
		} else if strings.HasPrefix(header.startline, "HTTP/1.0") {
			return 0
		} else {
			return -1
		}
	}
}

func (header *HTTPHeader) KeepAlive() bool {
	if header.headers["connection"] != nil {
		vals := strings.Split(header.headers["connection"].content, ",")
		for i := 0; i < len(vals); i++ {
			if strings.ToLower(strings.Trim(vals[i], " ")) == "close" {
				return false
			} else if strings.ToLower(strings.Trim(vals[i], " ")) == "keep-alive" {
				return true
			}
		}
	}
	return header.Version() == 1
}

func (header *HTTPHeader) Method() (string, error) {
	if !header.req {
		log.Panic("Asking HTTP method for a response!")
	}
	l := strings.Index(header.startline, " ")
	if l == -1 {
		return "", HTTP_INVALID_HEADER
	}
	return header.startline[:l], nil
}

func (header *HTTPHeader) ContentLength() (int64, error) {
	if header.req {
		method, err := header.Method()
		if err != nil {
			return 0, err
		}
		if method == "GET" || method == "HEAD" {
			return 0, nil
		}
	} else {
		status, err := header.Status()
		if err != nil {
			return 0, err
		}
		if status < 0 || status == 204 || status == 304 {
			return 0, nil
		}
	}
	if header.headers["transfer-encoding"] != nil {
		encs := strings.Split(header.headers["transfer-encoding"].content, ",")
		if strings.ToLower(strings.Trim(encs[len(encs)-1], " ")) == "chunked" {
			return HTTP_CONTENT_CHUNKED, nil
		} else {
			return HTTP_CONTENT_EOF, nil
		}
	}
	if header.headers["content-length"] != nil {
		return strconv.ParseInt(header.headers["content-length"].content, 10, 64)
	}
	if header.req {
		return 0, nil
	}
	return HTTP_CONTENT_EOF, nil
}

func (header *HTTPHeader) URL() (string, error) {
	if !header.req {
		log.Panic("Asking HTTP method for a response!")
	}
	start := strings.Index(header.startline, " ") + 1
	if start == 0 {
		return "", HTTP_INVALID_HEADER
	}
	l := strings.Index(header.startline[start:], " ")
	if l == -1 {
		return "", HTTP_INVALID_HEADER
	}
	return header.startline[start : start+l], nil
}

func (header *HTTPHeader) URLHost() (string, error) {
	url, err := header.URL()
	if err != nil {
		return "", err
	}
	start := strings.Index(url, "//") + 2
	if start == 1 {
		return "", HTTP_INVALID_HEADER
	}
	l := strings.Index(url[start:], "/")
	if l == -1 {
		return "", HTTP_INVALID_HEADER
	}
	return url[start : start+l], nil
}

func (header *HTTPHeader) URLRel() (string, error) {
	url, err := header.URL()
	if err != nil {
		return "", err
	}
	start := strings.Index(url, "//") + 2
	if start == 1 {
		return "", HTTP_INVALID_HEADER
	}
	l := strings.Index(url[start:], "/")
	if l == -1 {
		return "", HTTP_INVALID_HEADER
	}
	return url[start+l:], nil
}

func (header *HTTPHeader) Status() (int, error) {
	start := strings.Index(header.startline, " ") + 1
	if start == 0 {
		return 0, HTTP_INVALID_HEADER
	}
	l := strings.Index(header.startline[start:], " ")
	if l == -1 {
		return 0, HTTP_INVALID_HEADER
	}
	s, err := strconv.Atoi(header.startline[start : start+l])
	if err != nil {
		return 0, err
	}
	return s, nil
}

var return400 = []byte("HTTP/1.1 400 Bad Request\r\n\r\n")
var return502 = []byte("HTTP/1.1 502 Bad GateWay\r\n\r\n")

func HTTPWrite400(conn SSConn) error {
	return conn.SSWrite(&SSBuffer{buf: return400})
}
func HTTPWrite502(conn SSConn) error {
	return conn.SSWrite(&SSBuffer{buf: return502})
}

func HTTPWriteHeader(conn SSConn, header HTTPHeader) (err error) {
	headertxt := header.startline + "\r\n"
	if header.headers["host"] != nil {
		headertxt += header.headers["host"].field + ": " + header.headers["host"].content + "\r\n"
	}
	for k, v := range header.headers {
		if k == "host" || v == nil {
			continue
		}
		headertxt += v.field + ": " + v.content + "\r\n"
	}
	for _, v := range header.setCookies {
		headertxt += v.field + ": " + v.content + "\r\n"
	}
	headertxt += "\r\n"
	b := SSBuffer{buf: []byte(headertxt)}
	return conn.SSWrite(&b)
}

func HTTPPipeBody(in SSConn, buf *SSBuffer, out SSConn, header HTTPHeader, res chan error) {
	var err error
	defer func() { res <- err }()
	var l int64
	l, err = header.ContentLength()
	if err != nil {
		return
	}
	if l == HTTP_CONTENT_EOF {
		for {
			if err = out.SSWrite(buf); err != nil {
				return
			}
			if err = in.SSRead(buf); err != nil {
				if err == io.EOF {
					err = nil
					return
				}
				return
			}
		}
	} else if l == HTTP_CONTENT_CHUNKED {
		var line string
		var offset int
		var tofill int64
		offset = 0
		for {
			line, offset, err = HTTPReadLine(in, buf, offset)
			pcolon := strings.Index(line, ";")
			if pcolon != -1 {
				line = line[:pcolon]
			}
			tofill, err = strconv.ParseInt(line, 16, 32)
			if err != nil {
				return
			}
			if tofill > 0 {
				offset += int(tofill) + 2
			}
			for offset >= len(buf.buf) && offset > 0 {
				offset -= len(buf.buf)
				if err = out.SSWrite(buf); err != nil {
					return
				}
				if err = in.SSRead(buf); err != nil {
					return
				}
			}
			if tofill == 0 {
				break
			}
		}
		// trailer and final CRLF
		/*
		   for {
		       tbuf := make([]byte, offset)
		       copy(tbuf, buf.buf[:offset])
		       if err = out.SSWrite(&SSBuffer{buf:tbuf}); err != nil {
		           return
		       }
		       if offset == 2 {
		           break
		       }
		       copy(buf.buf, buf.buf[offset:])
		       buf.buf = buf.buf[:len(buf.buf) - offset]
		       _, offset, err = HTTPReadLine(in, buf, offset)
		   }
		*/
		// states 0d 0a 0d 0a
		state := 2
		for state != 4 {
			if len(buf.buf) == 0 {
				if err = in.SSRead(buf); err != nil {
					return
				}
			}
			for i := offset; i < len(buf.buf); i++ {
				if state == 3 && buf.buf[i] == 0x0a {
					state = 4
				} else if state == 2 && buf.buf[i] == 0x0d {
					state = 3
				} else if state == 1 && buf.buf[i] == 0x0a {
					state = 2
				} else if buf.buf[i] == 0x0d {
					state = 1
				} else {
					state = 0
				}
			}
			out.SSWrite(buf)
			offset = 0
		}
	} else {
		for {
			l -= int64(len(buf.buf))
			if err = out.SSWrite(buf); err != nil {
				return
			}
			if l == 0 {
				break
			}
			if err = in.SSRead(buf); err != nil {
				return
			}
		}
	}
}
