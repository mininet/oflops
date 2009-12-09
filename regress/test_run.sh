#!/bin/sh

sleep_time=12
setup_sleep=10		# !#&!@%$ IPv6 broadcasts for 10 seconds after bringing up an interface
./test_setup.sh $setup_sleep > /dev/null &
echo "Waiting $sleep_time seconds for IPv6 Broadcast discovery to go away... sigh"
sleep $sleep_time
../oflops -c lo -d veth3 -d veth5 ../example_modules/oflops_debug/.libs/liboflops_debug.so
./test_teardown.sh

