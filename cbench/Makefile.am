AUTOMAKE_OPTIONS=-Wall foreign

TOP=..

OFSRC=@openflowsrc@

CFLAGS+=-Wall -I$(OFSRC)/include -Wshadow 
LDFLAGS+=-L$(OFSRC)/lib 

bin_PROGRAMS=cbench


cbench_SOURCES = \
	cbench.c cbench.h \
	fakeswitch.c fakeswitch.h \
	msgbuf.c msgbuf.h
