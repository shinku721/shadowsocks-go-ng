shadowsocks-goo
===
Yet another shadowsocks implementation in Go.

Current status
---
Work in progress. Security is not well considered yet, and there may be some bugs in protocol implementations,
especially in HTTP proxy design due to the complexity of the specification.

**Please Help** I hope someone can check the implementation of HTTP proxy, since the specification is really complicated!  
Feel free to comment on the code, report bugs, or make feature requests. You're welcome!

Unexpected memory consumption is considered a bug. I assume that it consumes up to ~32K per connection.

Why one more implementation? (Design Consideration)
---
1. Lightweight
    - small executable
    - small memory footprint

    (These are due to go runtime, however.)
2. Compatibility
    - [ ] Compatible to libev version, including
        - [ ] command line options
        - [ ] config file
        - [ ] URI
    - [x] Cross-platform
3. Flexibility
    - [ ] Well-arranged source code making it easy to modify and extend
    - [ ] Multiple client protocol support on one port, including
        - [x] socks5
        - [x] socks4a
        - [x] HTTP proxy
        - [ ] iptables redir
    - [ ] Configurable ciphers and protocols through compiler flags
4. Documentation
    - [ ] Full documentation on the whole project
5. Security
    - [ ] Best-effort security

TODO
---
- [ ] Better log
- [ ] Handle server and client listener errors
