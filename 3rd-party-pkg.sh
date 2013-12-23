#!/bin/sh
# 3rd party packages suricata need
sudo apt-get install libpcre3 libpcre3-dbg libpcre3-dev  \
	build-essential autoconf automake libtool \
	libpcap-dev libnet1-dev \
	libyaml-0-2 libyaml-dev \
	zlib1g zlib1g-dev \
	libcap-ng-dev libcap-ng0 \
	libmagic-dev \
	libnetfilter-queue-dev libnetfilter-queue1 libnfnetlink-dev libnfnetlink0
