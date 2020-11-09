#!/bin/bash
set -e
set -u
TARGET_FILE="test.cpp"
if [[ -f ${TARGET_FILE} ]]; then
	mkdir build && cd build
	cmake .. && make
	exit 0
else
	echo -e "[ERROR]\n"
	exit 2
fi
