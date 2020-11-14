#pragma once
#include "SOCKS5_helpers.hpp"
#include <cstdint>
#include <memory>

// General Interface
class SOCKS5_Handle{
	protected:
		virtual int connect_proxy_socks5(const std::string& server_ip, std::uint16_t server_port, SOCKS5_RESOLVE dns_resol, 
				const std::string& proxy_username, const std::string& proxy_password) = 0;
	public:
		virtual int read_proxy(std::size_t, char*) = 0;
		virtual int write_proxy(std::size_t, const char*) = 0;
		int connect_proxy_socks(const std::string& server_ip, std::uint16_t server_port, SOCKS5_RESOLVE dns_resol,
				const std::string& proxy_username=nullptr, const std::string& proxy_password=nullptr){
			return this->connect_proxy_socks5(server_ip, server_port, dns_resol, proxy_username, proxy_password);
		}
		virtual ~SOCKS5_Handle() = default;
};

class SOCKS5_NOAUTH final : public SOCKS5_Handle{
	private:
		std::string _socks_serv_ip, _destination_addr;
		std::uint16_t _socks_serv_port, _destination_port;
		int _client_net_fd;
	public:
		SOCKS5_NOAUTH(const std::string& server_addr, std::uint16_t server_port);
		int read_proxy(std::size_t num_read, char* buffer) override;
		int write_proxy(std::size_t num_write, const char* buffer) override;
		int connect_proxy_socks5(const std::string& destination_addr, std::uint16_t destination_port, SOCKS5_RESOLVE dns_resol, 
				const std::string& proxy_username=nullptr, const std::string& proxy_password=nullptr) override;	
		int client_greeting() const noexcept;
		int client_connection_request() noexcept;
		~SOCKS5_NOAUTH() = default;
};

class SOCKS5_AUTH final : public SOCKS5_Handle{
	private:
		std::string _socks_serv_ip, _destination_addr;
		std::uint16_t _socks_serv_port, _destination_port;
		int _client_net_fd;
		std::string _proxy_username, _proxy_password;
	public:
		SOCKS5_AUTH(const std::string& server_addr, std::uint16_t server_port);
		int read_proxy(std::size_t num_read, char* buffer) override;
		int write_proxy(std::size_t num_write, const char* buffer) override;
		int connect_proxy_socks5(const std::string& destination_addr, std::uint16_t destination_port, SOCKS5_RESOLVE dns_resol, 
				const std::string& proxy_username, const std::string& proxy_password) override;
		int client_greeting() const noexcept;
		int client_connection_request() noexcept;
		int client_auth_handler() const;
		~SOCKS5_AUTH() = default;
};

class SOCKS5_Common{
	public:
		static int remote_DNS_client_connection_request(int, const std::string&, const std::uint16_t&) noexcept;
		static int client_connection_request(int, const std::string&, const std::uint16_t&) noexcept;
};

class SOCKS5_Factory{
	public:
		enum class SOCKS5_Type : std::uint8_t{
			SOCKS5_NOAUTH,
			SOCKS5_AUTH
		};
		static std::unique_ptr<SOCKS5_Handle> CreateSocksClient(SOCKS5_Type type, 
				const std::string& server_addr, std::uint16_t server_port){
			switch(type){
				case SOCKS5_Type::SOCKS5_NOAUTH:
					return std::make_unique<SOCKS5_NOAUTH>(server_addr, server_port);
				case SOCKS5_Type::SOCKS5_AUTH:
					return std::make_unique<SOCKS5_AUTH>(server_addr, server_port);
			}
			throw "Invalid SOCKS5 Proxy Type";
		}
};
