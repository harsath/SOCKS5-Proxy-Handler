#include "SOCKS5_proxy_handle.hpp"
#include "SOCKS5_helpers.hpp"
#include <cstdint>
#include <cstdlib>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <iostream>
#include <memory>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

// SOCKS5_NOAUTH implementation
SOCKS5_NOAUTH::SOCKS5_NOAUTH(const std::string& serv_ip, std::uint16_t server_port)
	: _socks_serv_ip{serv_ip}, _socks_serv_port{server_port} {}

int SOCKS5_NOAUTH::_set_destination_ip_type(const std::string& destination_ip) noexcept {
	addrinfo hints, *results, *temp;			
	char ip_str_buffer[INET_ADDRSTRLEN];
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	
	int status;
	if((status = getaddrinfo(destination_ip.c_str(), nullptr, &hints, &results)) != 0){
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		exit(EXIT_FAILURE);
	}
	for(temp = results; temp != nullptr; temp = temp->ai_next){
		if(temp->ai_family == AF_INET){
			sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(temp->ai_addr);
			inet_ntop(temp->ai_family, &ipv4->sin_addr, ip_str_buffer, INET6_ADDRSTRLEN);
		}
	}
	this->_destination_ip = ip_str_buffer;
	freeaddrinfo(results);
	return 0;
}

int SOCKS5_NOAUTH::connect_proxy_ip(const std::string &destination_ip, std::uint16_t destination_port){
	this->_set_destination_ip_type(destination_ip);
	// this->_destination_ip = destination_ip;
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
	if(server_choice[0] == 0x05 && server_choice[1] == 0x00){
		this->client_connection_request();
	}else{
		return -1;	
	}

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
	
	if(server_responce[0] == 0x05 && server_responce[1] == 0x00){
		return 0;
	}else{
		return -1;
	}

}

int SOCKS5_NOAUTH::write_proxy(std::size_t num_write, const char* buffer){
	SOCKS5::write_data(this->_client_net_fd, buffer, num_write, 0);
	return 0;
}

int SOCKS5_NOAUTH::read_proxy(std::size_t num_read, char *buffer){
	SOCKS5::read_data(this->_client_net_fd, buffer, num_read, 0);
	return 0;
}
