package shadowsocks

func DetectRedir(tconn SSConn) bool {
	return false
}

func (ctx *ClientContext) HandleRedir(tconn SSConn, buf *SSBuffer) error {
	return nil
}
