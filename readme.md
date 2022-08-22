### SOCKS5-Handler
![Linux Actions Status](https://github.com/harsath/SOCKS5-Proxy-Handler/workflows/Linux/badge.svg)

Sending and receiving message blocks/TCP stream over SOCKS5 proxy (running locally or over a network) with TCP sockets is a pain. I was frustrated when trying to send some TCP stream through a SOCKS5 server, so I implemented an abstraction over TCP sockets for this ***specific*** purpose. The interface is super easy to use; take a look at `example.cpp`.

#### Features:
- [x] Remote DNS resolution support (privacy)
- [x] Local IPv4 & DNS name resolution support
- [x] Client Authentication handler support (decoupled with NOAUTH)

(If you'd like to add something, please feel free to send a pull request or open an issue ticket.)

> Reference for client implementation: https://tools.ietf.org/html/rfc1928
	<br> RFC: 1928 (SOCKS Protocol Version 5)
	<br> RFC(Client Authentication): 1929(Username/Password Authentication for SOCKS V5)
