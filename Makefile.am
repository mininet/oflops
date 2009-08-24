AUTOMAKE_OPTIONS=-Wall foreign
#SUBDIRS = policies

OFSRC=@openflowsrc@

CFLAGS+=-I$(OFSRC)/include -Wshadow 
LDFLAGS+=-L$(OFSRC)/lib  -lpcap

LDADD=-ldl


bin_PROGRAMS=oflops

oflops_SOURCES= oflops.c oflops.h \
	utils.h utils.c \
	context.h context.c \
	control.h control.c \
	timer_event.h timer_event.c \
	usage.h usage.c \
	module_run.h  module_run.c \
	oflops_pcap.h oflops_pcap.c \
	test_module.h  test_module.c


count: 
	@wc -l $(oflops_SOURCES) | sort -n
