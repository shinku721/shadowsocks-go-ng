shadowsocks-goo
===
[![Travis Status](https://travis-ci.org/shinku721/shadowsocks-goo.svg?branch=master)](https://travis-ci.org/shinku721/shadowsocks-goo)
[![Appveyor Status](https://ci.appveyor.com/api/projects/status/32r7s2skrgm9ubva/branch/master?svg=true)](https://ci.appveyor.com/project/shinku721/shadowsocks-goo)

Yet another shadowsocks implementation in Go.

Current status
---
Work in progress. Security is not well considered yet, and there may be some bugs in protocol implementations,
especially in HTTP proxy design due to the complexity of the specification.

**Please Help** I hope someone can check the implementation of HTTP proxy, since the specification is really complicated!  
Feel free to comment on the code, report bugs, or make feature requests. You're welcome!

Unexpected memory consumption is considered a bug. I assume that it consumes up to ~32K per connection.

Supported Ciphers
---
- AEAD
  * chacha20-ietf-poly1305
  * aes-256-gcm
  * aes-192-gcm
  * aes-128-gcm
- Stream Ciphers (require `enable_stream_ciphers`, I beg you not to use these)
  * aes-256-cfb
  * aes-192-cfb
  * aes-128-cfb
  * aes-256-ctr
  * aes-192-ctr
  * aes-128-ctr

Supported Client Protocols
---
* socks5
* socks4a
* HTTP proxy
* iptables REDIRECT

Third Party Libraries
---
| Library |              URL               |
| ------- | ------------------------------ |
|  pflag  | https://github.com/spf13/pflag |
|  BoomFilters | https://github.com/tylertreat/BoomFilters |

TODO
---
- [ ] Better log format
- [x] Salt filter
- [ ] Compatibility
    - [ ] Compatible to libev version, including
        - [ ] command line options
        - [ ] config file
        - [ ] URI
    - [x] Cross-platform
- [ ] Extend config file format to support more functions
- [ ] Manager API
- [ ] Full documentation
- [ ] Client route control (PAC maybe)