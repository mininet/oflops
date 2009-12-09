TOP=../..
OFSRC=@openflowsrc@

CFLAGS+=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow 
LDFLAGS+=-L$(TOP)

LDADD=-ldl -lpcap -loflops_test


lib_LTLIBRARIES=liboflops_debug.la

liboflops_debug_la_SOURCES= debug.c
