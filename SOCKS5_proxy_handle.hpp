#pragma once
#include "SOCKS5_helpers.hpp"
#include <cstdint>
#include <memory>

// General Interface
class SOCKS5_Handle{
	public:
		virtual int read_proxy(std::size_t, void*) = 0;
		virtual int write_proxy(std::size_t, void*) = 0;
		virtual int connect_proxy_ip(const std::string&, std::uint16_t) = 0;
		virtual ~SOCKS5_Handle() = default;
};

class SOCKS5_NOAUTH final : public SOCKS5_Handle{
	private:
		std::string _socks_serv_ip, _destination_ip{};
		std::uint16_t _socks_serv_port;
		int _client_net_fd;
	public:
		explicit SOCKS5_NOAUTH(const std::string& server_ip, std::uint16_t server_port);
		int read_proxy(std::size_t num_read, void* buffer) override;
		int write_proxy(std::size_t num_write, void* buffer) override;
		int connect_proxy_ip(const std::string& destination_ip, std::uint16_t destination_port) override;	
};

class SOCKS5_Factory{
	public:
		enum class SOCKS5_Type : std::uint8_t{
			SOCKS5_NOAUTH
		};
		static std::unique_ptr<SOCKS5_Handle> CreateSocksClient(SOCKS5_Type type){
			switch(type){
				case SOCKS5_Type::SOCKS5_NOAUTH:
					return std::make_unique<SOCKS5_NOAUTH>();
					break;
			}
			throw "Invalid SOCKS5 Proxy Type";
		}
};
