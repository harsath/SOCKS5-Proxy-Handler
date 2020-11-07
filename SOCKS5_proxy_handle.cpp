#include "SOCKS5_proxy_handle.hpp"
#include "SOCKS5_helpers.hpp"
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <sys/socket.h>
#include <arpa/inet.h>

// SOCKS5_NOAUTH implementation
SOCKS5_NOAUTH::SOCKS5_NOAUTH(const std::string& serv_ip, std::uint16_t server_port)
	: _socks_serv_ip{serv_ip}, _socks_serv_port{server_port} {
		
	}
int SOCKS5_NOAUTH::connect_proxy_ip(const std::string &destination_ip, std::uint16_t destination_port){
	int sock_fd, ret;
	sockaddr_in server_addr;

	sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	SOCKS5::NEG_CHECK(sock_fd, "socket()");

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(destination_port);
	if(inet_pton(AF_INET, destination_ip.c_str(), &server_addr.sin_addr) <= 0){
		std::perror("inet_pton()");
		exit(EXIT_FAILURE);
	}
	ret = connect(sock_fd, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr));
	this->_client_net_fd = sock_fd;
	return sock_fd;
}
