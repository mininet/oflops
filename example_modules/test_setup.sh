#!/bin/sh

prefix=192.168.250
port=6633

if [ $# -gt 1 ] ; then
	prefix=$1
fi
if [ $# -gt 2 ] ; then
	port=$2
fi

export PATH=/sbin:$PATH

# add veth0,veth1
ip link add type veth
# add veth2,veth3
ip link add type veth
# add veth4,veth5
ip link add type veth

for p in 0 1 2 3 4 5 ; do
	ifconfig veth$p up
done

ifconfig veth0 $prefix.1 broadcast $prefix.255
ifconfig veth1 $prefix.2 broadcast $prefix.255

switch -iveth2,veth4 -d 010203040506 tcp:$prefix.1:$port

