#!/bin/sh

sleep_time=12
setup_sleep=10		# !#&!@%$ IPv6 broadcasts for 10 seconds after bringing up an interface
./test_setup.sh $setup_sleep > /dev/null &
echo "Waiting $sleep_time seconds for IPv6 Broadcast discovery to go away... sigh"
sleep $sleep_time
../.libs/oflops -c lo -d veth3 -d veth5 ../example_modules/openflow_packet_in/.libs/libof_packet_in.so
./test_teardown.sh

