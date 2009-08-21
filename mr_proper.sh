#!/bin/sh
set -x
if [ -f Makefile ] ; then
	make maintainer-clean
fi
rm -f aclocal.m4 configure depcomp install-sh missing Makefile.in regress/flow.log
rm -rf gmon.out
rm -f *~

