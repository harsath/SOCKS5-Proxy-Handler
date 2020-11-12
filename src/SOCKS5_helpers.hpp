#pragma once
#include <sys/types.h>
#include <sys/socket.h>
#include <asm-generic/socket.h>
#include <cstdlib>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <iostream>

// Defaults
enum class SOCKS5_DEFAULTS : std::uint8_t{
	RSV		= 0x00,
	SUPPORT_AUTH	= 0x02, 
	VERSION		= 0x05,
	VER_USERPASS	= 0x01
};

// Currently supported AUTH Types (0x00 is default)
enum class SOCKS5_AUTH_TYPES : std::uint8_t{
	NOAUTH		= 0x00,
	USERPASS	= 0x02,
};

// DNS resolve locally & make resolution on SOCKS5's endpoint
enum class SOCKS5_RESOLVE{
	REMOTE_RESOLVE = 0x01,
	LOCAL_RESOLVE = 0x02
};

// Anonymous SOCKS5 connect (NOAUTH default)
enum class SOCKS5_CGREETING_NOAUTH : std::uint8_t{
	VERSION		= static_cast<std::uint8_t>(SOCKS5_DEFAULTS::VERSION),
	NAUTH		= static_cast<std::uint8_t>(SOCKS5_DEFAULTS::SUPPORT_AUTH),
	AUTH		= static_cast<std::uint8_t>(SOCKS5_AUTH_TYPES::NOAUTH) 
};

// User/Pass SOCKS5 AUTH
enum class SOCKS5_CGREETING_AUTH : std::uint8_t{
	VERSION		= static_cast<std::uint8_t>(SOCKS5_DEFAULTS::VERSION),
	NAUTH		= static_cast<std::uint8_t>(SOCKS5_DEFAULTS::SUPPORT_AUTH),
	AUTH		= static_cast<std::uint8_t>(SOCKS5_AUTH_TYPES::USERPASS) 
};

enum class SOCKS5_ADDR_TYPE : std::uint8_t{
	IPv4		= 0x01,
	DOMAIN		= 0x03,
	IPv6		= 0x04
};

// SOCKS5 Client connection request commands
enum class SOCKS5_CCONNECTION_CMD : std::uint8_t{
	TCP_IP_STREAM	= 0x01,
	TCP_IP_PORT_BIND = 0x02,
	UDP_PORT	= 0x03
};

namespace SOCKS5{

inline static void NEG_CHECK(int value, const char* message){
	if(value < 0){
		std::perror(message);
		exit(EXIT_FAILURE);
	}
}

inline static int read_data(int net_file_des, char* buffer, int buff_read_len, int recv_flag){
	int recv_ret = recv(net_file_des, buffer, buff_read_len, recv_flag);	
	NEG_CHECK(recv_ret, "recv()");
	return 0;
}

inline static int write_data(int net_file_des, const char* buffer, int buff_write_len, int send_flags){
	int send_ret = send(net_file_des, buffer, buff_write_len, send_flags);	
	NEG_CHECK(send_ret, "send()");
	return 0;
}

static inline int create_socket_client(const char* name, std::uint16_t port){
	hostent* hoste;
	sockaddr_in addr;
	if((hoste = gethostbyname(name)) == nullptr){
		herror("gethostbyname()");
		exit(EXIT_FAILURE);
	}
	
	int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	NEG_CHECK(sock_fd,"socket()");

	addr.sin_addr = *(reinterpret_cast<in_addr*>(hoste->h_addr));
	addr.sin_port = htons(port);
	addr.sin_family = AF_INET;
	memset(addr.sin_zero, 0, 8);
	int connect_ret = connect(sock_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(sockaddr));
	NEG_CHECK(connect_ret, "connect()");
	return sock_fd;
}

// Local resolve
static inline int DNS_local_resolve(const std::string& destination_ip, std::string& _destination_ip) noexcept {
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
	_destination_ip = ip_str_buffer;
	freeaddrinfo(results);
	return 0;
}

} // end namespace SOCKS5
