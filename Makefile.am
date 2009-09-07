AUTOMAKE_OPTIONS=-Wall foreign

OFSRC=@openflowsrc@

CFLAGS+=-I$(OFSRC)/include -Wshadow 
LDFLAGS+=-L$(OFSRC)/lib 

LDADD=-ldl -lpcap -loflops_test


bin_PROGRAMS=oflops
lib_LTLIBRARIES=liboflops_test.la

oflops_SOURCES= oflops.c oflops.h \
	utils.h utils.c \
	context.h context.c \
	control.h control.c \
	timer_event.h timer_event.c \
	wc_event.h wc_event.c \
	usage.h usage.c \
	module_run.h  module_run.c \
	module_default.h  module_default.c \
	oflops_pcap.h oflops_pcap.c 

liboflops_test_la_SOURCES= test_module.h  test_module.c

SUBDIRS = example_modules

count: 
	@wc -l $(oflops_SOURCES) | sort -n
