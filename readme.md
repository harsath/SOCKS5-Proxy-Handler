### SOCKS5-Handler
![Linux Actions Status](https://github.com/harsath/SOCKS5-Proxy-Handler/workflows/Linux/badge.svg)

Sending and receiving message blocks/TCP stream over SOCKS5 proxy (running locally or through network) with UNIX sockets is a pain, I was frustrated myself trying to send TCP stream through a SOCKS5 server, so I implemented an abstraction over UNIX sockets for this ***specific*** purpose. The interface is super easy to use. Take a look at `example.cpp` for it's usage interface.

#### Features:
- [x] Remote DNS resolution support (privacy)
- [x] Local IPv4 & DNS name resolution support
- [x] Client Authentication handler support (decoupled with NOAUTH)

(I'm planning to implement more stuff, if you specifically need one, you can create an "Issue" or a Ticket)

> Reference for client implementation: https://tools.ietf.org/html/rfc1928
	<br> RFC: 1928 (SOCKS Protocol Version 5)
	<br> RFC(Client Authentication): 1929(Username/Password Authentication for SOCKS V5)
