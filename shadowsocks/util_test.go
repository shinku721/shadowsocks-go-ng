package shadowsocks

import (
  "testing"
)

func TestIsIP(t *testing.T) {
  if IsIP("127.0.0.1") != 4 {
    t.Fatal("IPv4")
  }
  if IsIP("fe80::1") != 6 {
    t.Fatal("IPv6")
  }
  if IsIP("1.2.3") != 0 {
    t.Fatal("Non-IP")
  }
}

func TestPackAddress(t *testing.T) {
  if PackAddress("127.0.0.1", 80) != "127.0.0.1:80" {
    t.Fatal("IPv4/Non-IP")
  }
  if PackAddress("fe80::1", 160) != "[fe80::1]:160" {
    t.Fatal("IPv6")
  }
}

func TestUnpackAddress(t *testing.T) {
  var host string
  var port uint16
  var err error
  if host, port, err = UnpackAddress("127.0.0.1:80"); err != nil || host != "127.0.0.1" || port != 80 {
    t.Fatal("IPv4/Non-IP")
  }
  if host, port, err = UnpackAddress("[fe80::1]:160"); err != nil || host != "fe80::1" || port != 160 {
    t.Fatal("IPv6")
  }
  if host, port, err = UnpackAddress("127.0.0.1"); err == nil {
    t.Fatal("No colon")
  }
  if host, port, err = UnpackAddress("[]:123"); err == nil {
    t.Fatal("Invalid IPv6")
  }
  if host, port, err = UnpackAddress("127.0.0.1:xx"); err == nil {
    t.Fatal("Invalid port")
  }
  if host, port, err = UnpackAddress("127.0.0.1:65537"); err == nil {
    t.Fatal("Invalid port")
  }
}

//func TestParseAddress(t *testing.T) {}