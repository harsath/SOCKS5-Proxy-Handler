#pragma once
#include "SOCKS5_helpers.hpp"
#include <cstdint>
#include <memory>

// General Interface
class SOCKS5_Handle{
	public:
		virtual int read_proxy(std::size_t, char*) = 0;
		virtual int write_proxy(std::size_t, const char*) = 0;
		virtual int connect_proxy_ip(const std::string& server_ip, std::uint16_t server_port) = 0;
		virtual ~SOCKS5_Handle() = default;
};

class SOCKS5_NOAUTH final : public SOCKS5_Handle{
	private:
		std::string _socks_serv_ip, _destination_ip;
		std::uint16_t _socks_serv_port, _destination_port;
		int _client_net_fd;
	public:
		SOCKS5_NOAUTH(const std::string& server_ip, std::uint16_t server_port);
		int read_proxy(std::size_t num_read, char* buffer) override;
		int write_proxy(std::size_t num_write, const char* buffer) override;
		int connect_proxy_ip(const std::string& destination_ip, std::uint16_t destination_port) override;	
		int client_greeting() noexcept;
		int client_connection_request() noexcept;
};

class SOCKS5_Factory{
	public:
		enum class SOCKS5_Type : std::uint8_t{
			SOCKS5_NOAUTH
		};
		static std::unique_ptr<SOCKS5_Handle> CreateSocksClient(SOCKS5_Type type, 
				const std::string& server_ip, std::uint16_t server_port){
			switch(type){
				case SOCKS5_Type::SOCKS5_NOAUTH:
					return std::make_unique<SOCKS5_NOAUTH>(server_ip, server_port);
			}
			throw "Invalid SOCKS5 Proxy Type";
		}
};
