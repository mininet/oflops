#!/bin/sh

#export PATH=/home/$USER/mine.of/bin:$PATH
export PATH=/home/ykk/openflow/openflow/switch:$PATH
prefix=192.168.250
port=6633
sleeptime=0

if [ $# -gt 0 ] ; then
	echo $0 : setting sleep time to $1 >&2
	sleeptime=$1
fi

if [ $# -gt 1 ] ; then
	prefix=$2
fi

if [ $# -gt 2 ] ; then
	port=$3
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

#ifconfig veth0 $prefix.2 broadcast $prefix.255
ifconfig veth1 $prefix.1 broadcast $prefix.255

# wait for IPv6 stupiditiy to subside
sleep $sleeptime
switch -iveth2,veth4 -d 010203040506 --max-backoff=1 tcp:127.0.0.1:$port

