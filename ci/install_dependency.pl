#!/bin/perl
use warnings;
use strict;

qx/sudo apt update -y/;
qx/sudo add-apt-repository ppa:ubuntu-toolchain-r\/test/;

my @install_apt_deps = (
	"ninja-build",
	"cmake",
	"gcc-9 g++-9"
);

print "\n\nInstalling APT dependencies\n\n";
for(@install_apt_deps){ system("sudo apt install $_ -y"); }
