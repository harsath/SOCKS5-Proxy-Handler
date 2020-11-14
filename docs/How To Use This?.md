#### How can I use this in my project?
Well, you just need to link the lib on your 
`CMakeLists.txt` file (if your using CMake based project) like this:

```cmake
	target_link_libraries(
		${YOUR_TARGET}
		libhandler
	)
```

How can I use the features you mentioned?
A very minimal usage is something like this:

```c++

	std::unique_ptr<SOCKS5_Handle> socket_handler =
			SOCKS5_Factory::CreateSocksClient(SOCKS5_Factory::SOCKS5_Type::SOCKS5_AUTH, "127.0.0.1", 9050);
	socket_handler->connect_proxy_socks("www.ipinfo.io", 80, SOCKS5_RESOLVE::REMOTE_RESOLVE, "user", "pass");

	std::string sample_request = "GET /ip HTTP/1.1\r\nHost: ipinfo.io\r\nUser-Agent: curl/7.65.2\r\n\r\n";

	socket_handler->write_proxy(sample_request.size(), sample_request.c_str());

	constexpr std::size_t reply_buff_size = 2048;

	char* read_buffer_reply =  new char[reply_buff_size];

	socket_handler->read_proxy(reply_buff_size, read_buffer_reply);
```

### API Docs:

```
	std::unique_ptr<SOCKS5_Handle> = SOCKS5_Factory::CreateSocksClient(
				TYPE_OF_SOCKS_SERVER_YOUR_CONNECTING(Anonymous or Requires User/Pass),
				SOCKS5_SERVER_ADDRESS_IPv4,
				SOCKS5_SERVER_PORT
			);

		connect_proxy_socks(
				WEBSITE_YOU_WANNA_CONNECT_TO_THROUGH_SOCKS5,
				WEBSITE_OR_SERVER's_PORT,
				RESOLVE_DOMAIN_LOCALLY_OR_MAKE_RESOLUTION_AT_SOCKS5's_END,
				(Optional) SOCKS5_SERVER_USERNAME (If it requires),
				(Optional) SOCKS5_SERVER_PASSWORD (If it requires)
				)

		write_proxy(
				SIZE_BUFFER_YOU_WANNA_SEND_THROUGH_SOCKS5_PROXY,
				ACTUAL_BUFFER_YOU_WANNA_SEND_THROUGH_SOCKS5_PROXY
			   )

		read_proxy(
				SIZE_OF_BUFFER_YOU_WANNA_READ_FROM_WEBSITE_THROUGH_SOCKS5_PROXY,
				POINTER_TO_BUFFER_MEMORY
			  )
```


#### Types of SOCKS5:-
		* `SOCKS5_Factory::SOCKS5_Type::SOCKS5_AUTH` : Proxy that requires Auth
		* `SOCKS5_Factory::SOCKS5_Type::SOCKS5_NOAUTH` : Anonymous SOCKS5 Proxy

#### Types of DNS Resolution:
		* `SOCKS5_RESOLVE::REMOTE_RESOLVE` : Forward DNS resolution to Proxy's end (DNS name resolution will NOT takeplace at your machine/host for privacy)
		* `SOCKS5_RESOLVE::LOCAL_RESOLVE` : Resolve DNS names on your machine/host.

It's that easy, I wanted to make it real simple for people to do this task ;)
