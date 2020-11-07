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
	SUPPORT_AUTH	= 0x01
};

// Currently supported AUTH Types (0x00 is default)
enum class SOCKS5_AUTH_TYPES : std::uint8_t{
	NOAUTH		= 0x00,
	USERPASS	= 0x02,
};

// Anonymous SOCKS5 connect (NOAUTH default)
enum class SOCKS5_CGREETING_NOAUTH : std::uint8_t{
	VERSION		= 0x05,
	NAUTH		= static_cast<std::uint8_t>(SOCKS5_DEFAULTS::SUPPORT_AUTH),
	AUTH		= static_cast<std::uint8_t>(SOCKS5_AUTH_TYPES::NOAUTH) 
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

inline static int read_data(int net_file_des, void* buffer, int buff_read_len){
	int num_read, remain = buff_read_len;			
	while(remain > 0){
		if((num_read = read(net_file_des, buffer, remain)) < 0){
			if(errno == EINTR || errno == EAGAIN){ continue; }
			else{
				if(num_read == 0){
					return 0;
				}else{
					remain -= num_read;
					buff_read_len += num_read;
				}
			}
		}
	}
	return buff_read_len;
}

inline static int write_data(int net_file_des, void* buffer_, int buff_write_len){
	int num_write, remain = buff_write_len;	
	char* buffer = (char*)buffer_;
	while(remain > 0){
		// std::cout << "Writign it here" << std::endl;
		if((num_write = write(net_file_des, buffer, remain)) == -1){
			if(errno == EINTR || errno == EAGAIN){ continue; }
			else{
				if(num_write == buff_write_len){
					return 0;
				}else{
					std::cout << num_write << std::endl;
					remain -= num_write;
					buff_write_len += num_write;
				}
			}
		}
	}
	return num_write;
}

inline static void NEG_CHECK(int value, const char* message){
	if(value < 0){
		std::perror(message);
		exit(EXIT_FAILURE);
	}
}

static inline int create_socket_INADDR_ANY(int port, std::size_t backlog){
	int sock_fd, ret;
	sockaddr_in local;

	sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	NEG_CHECK(sock_fd, "socket()");

	int optval = 1;
	ret = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	NEG_CHECK(ret, "setsockopt()");

	memset(&local, 0, sizeof(local));
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_family = AF_INET;
	local.sin_port = htons(port);

	ret = bind(sock_fd, reinterpret_cast<sockaddr*>(&local), sizeof(local));
	NEG_CHECK(ret, "bind()");

	ret = listen(sock_fd, backlog);
	NEG_CHECK(ret, "listen()");

	return sock_fd;

}

} // end namespace SOCKS5










