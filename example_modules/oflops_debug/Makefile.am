TOP=../..
OFSRC=@openflowsrc@

CFLAGS+=-I$(OFSRC)/include -I$(TOP) -Wshadow 
LDFLAGS+=-L$(TOP)

LDADD=-ldl -lpcap -ltest_module


lib_LTLIBRARIES=liboflops_debug.la

liboflops_debug_la_SOURCES= debug.c
