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

int SOCKS5_NOAUTH::connect_proxy_socks5(const std::string &destination_addr, std::uint16_t destination_port, SOCKS5_RESOLVE dns_resol){
	if(dns_resol == SOCKS5_RESOLVE::LOCAL_RESOLVE){
		SOCKS5::DNS_local_resolve(destination_addr, this->_destination_addr);
		this->_destination_port = destination_port;

		int cli_sock_fd = SOCKS5::create_socket_client(this->_socks_serv_ip.c_str(),  this->_socks_serv_port);

		this->_client_net_fd = cli_sock_fd;
		this->client_greeting();

		return cli_sock_fd;
	}else{
		this->_destination_addr = destination_addr;		

		int cli_sock_fd = SOCKS5::create_socket_client(this->_socks_serv_ip.c_str(),  this->_socks_serv_port);

		this->_client_net_fd = cli_sock_fd;
		this->remote_DNS_client_connection_request();
		return cli_sock_fd;
	}
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

int SOCKS5_NOAUTH::remote_DNS_client_connection_request() noexcept {
	// [VERSION, SOCKS_CMD, RESV(0x00), (SOCKS5 DNS Addr Type)[0x03, Domain Name], DST_PORT]
	constexpr std::size_t num_bytes = 1 + 1 + 1 + (1 + sizeof(_destination_addr.c_str())) + 2;
	char* domain_addr_buffer = strdup(this->_destination_addr.c_str());

	char port_n[2] = { 
		static_cast<char>(this->_destination_port>>8), 
		static_cast<char>(this->_destination_port)
	};

	char client_conn_request[num_bytes] = {
		static_cast<char>(SOCKS5_CGREETING_NOAUTH::VERSION),
		static_cast<char>(SOCKS5_CCONNECTION_CMD::TCP_IP_STREAM),
		static_cast<char>(SOCKS5_DEFAULTS::RSV),
		static_cast<char>(SOCKS5_ADDR_TYPE::IPv4),
		// *domain_addr_buffer,
		// port_n[0], port_n[1]
	};
	
	for(std::size_t i{}; this->_destination_addr.size(); i++){
		client_conn_request[i+4] = this->_destination_addr.c_str()[i];
	}

	int write_ret = SOCKS5::write_data(this->_client_net_fd, client_conn_request, sizeof(client_conn_request), 0);

	constexpr std::size_t reply_bytes = 1 + 1 + 1 + 1 + (1 + sizeof(this->_destination_addr)) + 2;
	char server_responce[reply_bytes];
	int read_ret = SOCKS5::read_data(this->_client_net_fd, server_responce, sizeof(server_responce), 0);
	
	if(server_responce[0] == 0x05 && server_responce[1] == 0x00){
		return 0;
	}else{
		return -1;
	}
	free(domain_addr_buffer);
}

// Local DNS resolved request handler
int SOCKS5_NOAUTH::client_connection_request() noexcept {
	// [VERSION, SOCKS_CMD, RESV(0x00), (SOCKS5 Addr Type)[TYPE, ADDR], DST_PORT]
	constexpr std::size_t num_bytes = 1 + 1 + 1 + (1 + 4) + 2;
	char ipv4_buffer[4];
	int inet_ret = inet_pton(AF_INET, this->_destination_addr.c_str(), ipv4_buffer);

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
