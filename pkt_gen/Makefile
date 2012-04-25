#
# simple program to see how stanford packet generator
# can be integrated in a c program 
#

all: pkt_gen

pkt_gen: pkt_gen.c common/nf2util.o
	gcc -g -c pkt_gen.c
	gcc -g -lm common/nf2util.o pkt_gen.o -o pkt_gen

common/nf2util.o: common/nf2.h common/nf2util.c common/nf2util.h common/reg_defines.h common/util.c common/util.h
	make -C common/

clean:
	rm -rf *.o pkt_gen *~