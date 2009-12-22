#!/bin/sh
set -x
if [ -f Makefile ] ; then
	make maintainer-clean
fi
rm -f aclocal.m4 configure depcomp install-sh missing config.guess config.sub ltmain.sh
find . -name Makefile.in | xargs rm -f 
rm -rf gmon.out
rm -f *~

