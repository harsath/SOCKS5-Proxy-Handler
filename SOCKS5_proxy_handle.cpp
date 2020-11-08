#include "SOCKS5_proxy_handle.hpp"
#include "SOCKS5_helpers.hpp"
#include <cstdint>
#include <cstdlib>
#include <unistd.h>
#include <iostream>
#include <memory>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>

// SOCKS5_NOAUTH implementation
SOCKS5_NOAUTH::SOCKS5_NOAUTH(const std::string& serv_ip, std::uint16_t server_port)
	: _socks_serv_ip{serv_ip}, _socks_serv_port{server_port} {
		
	}

int SOCKS5_NOAUTH::connect_proxy_ip(const std::string &destination_ip, std::uint16_t destination_port){
	this->_destination_ip = destination_ip;
	this->_destination_port = destination_port;

	int cli_sock_fd = SOCKS5::create_socket_client(this->_socks_serv_ip.c_str(),  this->_socks_serv_port);

	this->_client_net_fd = cli_sock_fd;
	this->client_greeting();

	return cli_sock_fd;
}

int SOCKS5_NOAUTH::client_greeting() noexcept {
	char client_greeting_msg[3]; 
	// [VERSION, NAUTH, AUTH]
	client_greeting_msg[0] = static_cast<char>(SOCKS5_CGREETING_NOAUTH::VERSION);
	client_greeting_msg[1] = static_cast<char>(SOCKS5_DEFAULTS::SUPPORT_AUTH);
	client_greeting_msg[2] = static_cast<char>(SOCKS5_AUTH_TYPES::NOAUTH);

	int write_ret = SOCKS5::write_data(this->_client_net_fd, client_greeting_msg, sizeof(client_greeting_msg), 0);

	char server_choice[2];
	int read_ret = SOCKS5::read_data(this->_client_net_fd, server_choice, sizeof(server_choice), 0);
	// if(server_choice[0] == 0x05 && server_choice[1] == 0x00){
	// 	std::cout << "Server accepted!" << std::endl;
	// }else{
	// 	std::cout << "NO, We got failed" << std::endl;
	// }

	this->client_connection_request();

	return 0;
}

int SOCKS5_NOAUTH::client_connection_request() noexcept {
	// [VERSION, SOCKS_CMD, RESV(0x00), (SOCKS5 Addr Type)[TYPE, ADDR], DST_PORT]
	constexpr std::size_t num_bytes = 1 + 1 + 1 + (1 + 4) + 2;
	char ipv4_buffer[4];
	int inet_ret = inet_pton(AF_INET, this->_destination_ip.c_str(), ipv4_buffer);

	char port_n[2] = { 
		static_cast<char>(this->_destination_port>>8), 
		static_cast<char>(this->_destination_port)
	};

	char client_conn_request[num_bytes] = {
		static_cast<char>(SOCKS5_CGREETING_NOAUTH::VERSION),
		static_cast<char>(SOCKS5_CCONNECTION_CMD::TCP_IP_STREAM),
		static_cast<char>(SOCKS5_DEFAULTS::RSV),
		static_cast<char>(SOCKS5_ADDR_TYPE::IPv4),
		static_cast<char>(ipv4_buffer[0]),
		static_cast<char>(ipv4_buffer[1]),
		static_cast<char>(ipv4_buffer[2]),
		static_cast<char>(ipv4_buffer[3]),
		port_n[0], port_n[1]
	};

	int write_ret = SOCKS5::write_data(this->_client_net_fd, client_conn_request, sizeof(client_conn_request), 0);

	constexpr std::size_t reply_bytes = 1 + 1 + 1 + 1 + (1 + 4) + 2;
	char server_responce[reply_bytes];
	int read_ret = SOCKS5::read_data(this->_client_net_fd, server_responce, sizeof(server_responce), 0);
	
	// if(server_responce[0] == 0x05 && server_responce[1] == 0x00){
	// 	std::cout << "Yes, Granted!" << std::endl;
	// }else{
	// 	std::cout << "Nope, Not granted!" << std::endl;
	// }

	constexpr std::size_t cli_read_buffer_size = 2048;
	char* cli_read_buffer = (char*)new char[cli_read_buffer_size];

	char request[1028] = "GET /json HTTP/1.1\r\nHost: 95.217.228.176\r\nUser-Agent: curl/7.65.2\r\nAccept: */*\r\n\r\n";

	SOCKS5::write_data(this->_client_net_fd, request, 1028, 0);

	SOCKS5::read_data(this->_client_net_fd, cli_read_buffer, cli_read_buffer_size, 0);

	std::cout << cli_read_buffer << std::endl;

	delete[] cli_read_buffer;

	return 0;
}

int SOCKS5_NOAUTH::write_proxy(std::size_t num_write, void* buffer){
	return 1;
}
