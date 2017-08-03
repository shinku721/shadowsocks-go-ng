package shadowsocks

type SSError struct {
	message   string
	authError bool
}

func (e *SSError) Error() string {
	return e.message
}

func NewError(message string) error {
	return &SSError{
		message:   message,
		authError: false,
	}
}

func NewAuthError(message string) error {
	return &SSError{
		message:   message,
		authError: true,
	}
}

func IsAuthError(err error) bool {
	if e, ok := err.(*SSError); ok {
		return e.authError
	}
	return false
}

var ERR_HTTP_INVALID_HEADER = NewError("Invalid HTTP header")
var ERR_HTTP_HOST_TOO_LONG = NewError("HTTP host too long")
var ERR_HTTP_MANAGER_DEAD = NewError("HTTP manager is dead")

var ERR_SOCKS4_INVALID_PROTOCOL = NewError("Invalid socks4 protocol")
var ERR_SOCKS4_COMMAND_NOT_SUPPORTED = NewError("Unsupported socks4 command")

var ERR_SOCKS5_INVALID_PROTOCOL = NewError("Invalid socks5 protocol")
var ERR_SOCKS5_NO_VALID_AUTH = NewError("Socks5 request requires auth")
var ERR_SOCKS5_COMMAND_NOT_SUPPORTED = NewError("Unsupported socks5 command")

var ERR_AUTH_FAIL = NewAuthError("Authentication failure")
var ERR_DUP_SALT = NewAuthError("Duplicated salt (maybe replay attack)")
var ERR_INVALID_CHUNK_SIZE = NewError("Invalid chunk size")
var ERR_MAX_CHUNK_SIZE_EXCEED = NewError("Maximum chunk size exceeded")

var ERR_SERVER_NOT_EXIST = NewError("Server does not exist")
var ERR_UNIMPLEMENTED = NewError("Unimplemented")
var ERR_INVALID_ADDR_TYPE = NewError("Invalid address type")

var ERR_BUF_SIZE_EXCEED = NewError("Maximum buffer size exceeded")

var ERR_INVALID_ADDR = NewError("Invalid address")
