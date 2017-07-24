package shadowsocks

type SaltFilter interface {
  Contains(salt []byte) bool
  Add(salt []byte)
}

var saltFilter SaltFilter