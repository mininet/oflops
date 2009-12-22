AUTOMAKE_OPTIONS=-Wall foreign

TOP=..

OFSRC=@openflowsrc@

CFLAGS+=-Wall -I$(OFSRC)/include -Wshadow 
LDFLAGS+=-L$(TOP) -loflops_test

bin_PROGRAMS=cbench


cbench_SOURCES = \
	cbench.c cbench.h \
	fakeswitch.c fakeswitch.h 

