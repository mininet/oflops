TOP=../..
OFSRC=@openflowsrc@

CFLAGS+=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow 
LDFLAGS+=-L$(TOP) -lm

LDADD=-ldl -lpcap -loflops_test


lib_LTLIBRARIES=libsnmp_queue_delay.la

libsnmp_queue_delay_la_SOURCES= queue_delay.c