TOP=../..
OFSRC=@openflowsrc@

CFLAGS+=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow # -I$(OFSRC)/lib
LDFLAGS+=-L$(TOP) -lm -L$(OFSRC)/lib/

LDADD=-ldl -lpcap -loflops_test -lopenflow

lib_LTLIBRARIES=libopenflow_action_delay.la

libopenflow_action_delay_la_SOURCES= action_delay.c # msg.h msg.c # vconn.c
