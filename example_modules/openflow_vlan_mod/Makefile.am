TOP=../..
OFSRC=@openflowsrc@

CFLAGS+=-Wall -I$(OFSRC)/include -I$(TOP) -Wshadow # -I$(OFSRC)/lib
LDFLAGS+=-L$(TOP) -L$(OFSRC)/lib/

LDADD=-ldl -lpcap -loflops_test -lopenflow -lm

lib_LTLIBRARIES=libopenflow_vlan_mod.la

libopenflow_vlan_mod_la_SOURCES=vlan_mod.c
