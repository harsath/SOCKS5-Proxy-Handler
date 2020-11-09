set(LIB_BIN_NAME libhandler)

set(
	SRC_LIB_FILES
	./SOCKS5_helpers.hpp
	./SOCKS5_proxy_handle.cpp
	./SOCKS5_proxy_handle.hpp
	)

add_library(
	${LIB_BIN_NAME}
	STATIC ${SRC_LIB_FILES}
	)

set_target_properties(
	${LIB_BIN_NAME}
	PROPERTIES LINKER_LANGUAGE CXX
	)

target_compile_options(
	${LIB_BIN_NAME}
	PRIVATE -g -Wall -O3
	)
