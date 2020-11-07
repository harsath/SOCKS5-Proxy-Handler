#include "SOCKS5_proxy_handle.hpp"
#include <iostream>
#include <memory>

int main(int argc, char *argv[]){
	std::unique_ptr<SOCKS5_Handle> foo = 
		SOCKS5_Factory::CreateSocksClient(SOCKS5_Factory::SOCKS5_Type::SOCKS5_NOAUTH, "127.0.0.1", 9050);
	
	return 0;
}
