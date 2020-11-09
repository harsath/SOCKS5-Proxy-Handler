#!/bin/bash
set -e
set -u
SOCKS_LINK_FILE=$PWD/SOCKS5_proxy_handle.cpp
SOCKS_TEST_FILE=$PWD/test.cpp
BUILD_OUT_BIN="socks_test"
COMPILER="g++"
COMPILER_FLAGS=" -Wall -std=c++17 -o "
if [[ -f ${SOCKS_LINK_FILE} ]] && [[ -f $SOCKS_TEST_FILE ]]; then
	${COMPILER} ${COMPILER_FLAGS} ${BUILD_OUT_BIN} ${SOCKS_LINK_FILE} ${SOCKS_TEST_FILE} 2>/dev/null
	./${BUILD_OUT_BIN}
	exit 0
else
	echo -e "[ERROR]\n"
	exit 2
fi
