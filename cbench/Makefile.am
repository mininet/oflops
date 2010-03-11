AUTOMAKE_OPTIONS=-Wall foreign

TOP=..

OFSRC=@openflowsrc@

CFLAGS+=-Wall -I$(OFSRC)/include -Wshadow 
LDFLAGS+=-L$(TOP) -static -lm -loflops_test

bin_PROGRAMS=cbench


cbench_SOURCES = \
	myargs.c myargs.h \
	cbench.c cbench.h \
	fakeswitch.c fakeswitch.h 

