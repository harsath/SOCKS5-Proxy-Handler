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
	int cli_sock_fd = SOCKS5::create_socket_client(this->_socks_serv_ip.c_str(),  this->_socks_serv_port);

	this->_client_net_fd = cli_sock_fd;
	this->client_greeting();

	return cli_sock_fd;
}

void SOCKS5_NOAUTH::client_greeting() noexcept {
	char client_greeting_msg[3]; 
	// [VERSION, NAUTH, AUTH]
	client_greeting_msg[0] = static_cast<char>(SOCKS5_CGREETING_NOAUTH::VERSION);
	client_greeting_msg[1] = static_cast<char>(SOCKS5_DEFAULTS::SUPPORT_AUTH);
	client_greeting_msg[2] = static_cast<char>(SOCKS5_AUTH_TYPES::NOAUTH);

	int write_ret = SOCKS5::write_data(this->_client_net_fd, client_greeting_msg, sizeof(client_greeting_msg), 0);

}

int SOCKS5_NOAUTH::write_proxy(std::size_t num_write, void* buffer){
	return 1;
}
