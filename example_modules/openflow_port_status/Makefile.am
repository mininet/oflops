TOP=../..
OFSRC=@openflowsrc@

CFLAGS+=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow 
LDFLAGS+=-L$(TOP)

LDADD=-ldl -lpcap -loflops_test


lib_LTLIBRARIES=libof_port_stat.la

libof_port_stat_la_SOURCES= portstat.c
