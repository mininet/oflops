AUTOMAKE_OPTIONS=-Wall foreign

OFSRC=@openflowsrc@

CFLAGS+=-Wall -I$(OFSRC)/include -Wshadow 
LDFLAGS+=-L$(OFSRC)/lib 

LDADD=-ldl -lpcap -lnetsnmp -loflops_test 
#LDADD+=-lefence

EXTRA_DIST=./doc

bin_PROGRAMS=oflops
lib_LTLIBRARIES=liboflops_test.la

liboflops_test_la_SOURCES= test_module.h  test_module.c \
	msgbuf.c msgbuf.h \
	pcap_track.c  pcap_track.h \
	oflops_snmp.c oflops_snmp.h \
	utils.h utils.c \
	wc_event.h wc_event.c 
liboflops_test_la_LIBADD=-lnetsnmp

oflops_SOURCES= \
	channel_info.h channel_info.c \
	context.h context.c \
	control.h control.c \
	module_run.h  module_run.c \
	module_default.h  module_default.c \
	oflops.c oflops.h \
	oflops_pcap.h oflops_pcap.c \
	timer_event.h timer_event.c \
	usage.h usage.c 
oflops_LDFLAGS=-static -Wl,-E


# lame; add "." before anything else to force dependencies
#	to be built right
SUBDIRS = . example_modules cbench doc

docs: 
	$(MAKE) -c doc docs

count: 
	@wc -l `find . -name \*.c -o -name \*.h -o -name Makefile.am` | sort -n
