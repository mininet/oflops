AUTOMAKE_OPTIONS=-Wall -Werror foreign
#SUBDIRS = policies

OFSRC=@openflowsrc@

CFLAGS+=-I$(OFSRC)/include -I$(OFSRC)/lib -Wshadow
LDFLAGS+=-L$(OFSRC)/lib 

LDADD=$(OFSRC)/lib/libopenflow.a -ldl


bin_PROGRAMS=oflops

oflops_SOURCES= oflops.c \
	context.h control.h module_run.h oflops.h \
	oflops_pcap.h test_module.h usage.h 


count: 
	@wc -l $(flowvisor_SOURCES) $(flowvisor_HEADERS) | sort -n
