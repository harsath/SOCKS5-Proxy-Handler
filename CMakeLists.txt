cmake_minimum_required(VERSION 3.10)

project(
	socks_handler
	DESCRIPTION "SOCKS5 Proxy client handler"
	LANGUAGES CXX
	)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(EXEC_FILES ./test.cpp)

add_subdirectory(./src)
include_directories(./src)

add_executable(
	${PROJECT_NAME}
	${EXEC_FILES}
	)

target_link_libraries(
	${PROJECT_NAME}
	libhandler
	)
target_compile_options(
	${PROJECT_NAME}
	PRIVATE
	-Wall -O3
	)
