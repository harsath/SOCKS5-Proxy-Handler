### SOCKS5-Handler
[![Build Status](https://travis-ci.org/harsathAI/SOCKS5-Proxy-Handler.svg?branch=master)](https://travis-ci.org/harsathAI/SOCKS5-Proxy-Handler)

Sending and receiving message blocks/TCP stream over SOCKS5 proxy (running locally or through network) with UNIX sockets is a pain, I was frustrated myself trying to send TCP stream through a SOCKS5 server, so I implemented an abstraction over UNIX sockets for this ***specific*** purpose. The interface is super easy to use. Take a look at `test.cpp` for it's usage interface.

(Im planning to add more things soon...)
- [x] Remote DNS resolution support (privacy)
- [x] Local IPv4 & Domain name resolution support
- [ ] Client Auth support(decoupled with NOAUTH) {Working....}


> Reference for client implementation: https://tools.ietf.org/html/rfc1928
	<br> RFC: 1928 (SOCKS Protocol Version 5)
