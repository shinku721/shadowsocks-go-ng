// +build debug

package shadowsocks

import "fmt"

var connLog = make(map[string][]string)

type dstart struct{ conn SSConn }
type dstop struct{ conn SSConn }
type dlog struct {
	conn SSConn
	log  string
}

var ch = make(chan interface{})

func init() {
	go func() {
		for {
			msg := <-ch
			if s, ok := msg.(dstart); ok {
				connLog[s.conn.RemoteAddr()] = []string{}
			} else if s, ok := msg.(dstop); ok {
				delete(connLog, s.conn.RemoteAddr())
			} else if s, ok := msg.(dlog); ok {
				if ls, ok := connLog[s.conn.RemoteAddr()]; ok {
					connLog[s.conn.RemoteAddr()] = append(ls, s.log)
				}
			}
		}
	}()
}

func TrackConnStart(conn SSConn) {
	ch <- dstart{conn}
}

func TrackConnLog(conn SSConn, format string, a ...interface{}) {
	ch <- dlog{conn: conn, log: fmt.Sprintf(format, a...)}
}

func TrackConnStop(conn SSConn) {
	ch <- dstop{conn}
}

func TrackPrintAll() (res string) {
	res = ""
	for c, l := range connLog {
		res += fmt.Sprintf("connection %s:\n", c)
		for _, v := range l {
			res += fmt.Sprintf("\t%s\n", v)
		}
	}
	return
}
