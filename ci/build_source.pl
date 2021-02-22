#!/bin/perl
use warnings;
use strict;

if($#ARGV+1 != 1){ print "Usage: ./script.pl <BUILD DIR>"; exit 2; }

unless(-d $ARGV[0]){
	mkdir($ARGV[0]); chdir($ARGV[0]);
	system("cmake -GNinja .. && ninja");
}else{
	print "\n\nGiven build dir already exists, remove that fist\n\n";
	exit(2);
}
