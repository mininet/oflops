AUTOMAKE_OPTIONS=-Wall foreign

OFSRC=@openflowsrc@

CFLAGS+=-Wall -I$(OFSRC)/include -Wshadow 
LDFLAGS+=-L$(OFSRC)/lib 

LDADD=-ldl -lpcap -loflops_test 
#LDADD+=-lefence

EXTRA_DIST=./doc


bin_PROGRAMS=oflops
lib_LTLIBRARIES=liboflops_test.la

oflops_SOURCES= \
	channel_info.h channel_info.c \
	context.h context.c \
	control.h control.c \
	module_run.h  module_run.c \
	module_default.h  module_default.c \
	oflops.c oflops.h \
	oflops_pcap.h oflops_pcap.c \
	pcap_track.c  pcap_track.h \
	timer_event.h timer_event.c \
	usage.h usage.c \
	utils.h utils.c \
	wc_event.h wc_event.c 

liboflops_test_la_SOURCES= test_module.h  test_module.c

SUBDIRS = example_modules

docs: 
	cd doc  && doxygen doc.cfg
	@echo Generated HTML and Latex docs under ./doc

count: 
	@wc -l $(oflops_SOURCES) | sort -n
