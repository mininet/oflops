TOP=../..
OFSRC=@openflowsrc@

CFLAGS+=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow 
LDFLAGS+=-L$(TOP) -lm

LDADD=-ldl -lpcap -loflops_test

lib_LTLIBRARIES=libof_packet_out.la

libof_packet_out_la_SOURCES= packet_out.c