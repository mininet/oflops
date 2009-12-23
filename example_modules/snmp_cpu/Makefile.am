TOP=../..
OFSRC=@openflowsrc@

CFLAGS+=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow 
LDFLAGS+=-L$(TOP)

LDADD=-ldl -lpcap -loflops_test

lib_LTLIBRARIES=libof_snmp_cpu.la

libof_snmp_cpu_la_SOURCES= snmpcpu.c
