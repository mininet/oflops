TOP=../..
OFSRC=@openflowsrc@

CFLAGS+=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow 
LDFLAGS+=-L$(TOP) -L$(OFSRC)/lib/

LDADD=-ldl -lpcap -loflops_test -lopenflow

lib_LTLIBRARIES=libopenflow_dummy.la

libopenflow_dummy_la_SOURCES= dummy.c # vconn.c