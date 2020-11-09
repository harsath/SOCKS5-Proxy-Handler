#include "SOCKS5_proxy_handle.hpp"
#include <iostream>
#include <memory>

int main(int argc, char *argv[]){
	std::unique_ptr<SOCKS5_Handle> socket_handler = 
		SOCKS5_Factory::CreateSocksClient(SOCKS5_Factory::SOCKS5_Type::SOCKS5_NOAUTH, "127.0.0.1", 9050);
	socket_handler->connect_proxy_ip("95.217.228.176", 80); // connecting to public ip check site through Tor daemon's SOCKS server

	// Reading the data;
	std::string sample_request = "GET /json HTTP/1.1\r\nHost: 95.217.228.176\r\nUser-Agent: curl/7.65.2\r\n\r\n";
	
	socket_handler->write_proxy(sample_request.size(), sample_request.c_str());	

	constexpr std::size_t reply_buff_size = 2048;
	char* read_buffer_reply =  new char[reply_buff_size];

	socket_handler->read_proxy(reply_buff_size, read_buffer_reply);

	std::cout << read_buffer_reply << std::endl;

	delete[] read_buffer_reply;

	return 0;
}
