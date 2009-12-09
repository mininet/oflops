#!/bin/sh

# Short cuts for building a dev build... just to save some key strokes

sh boot.sh
./configure $@ CFLAGS="-O0 -g -Werror" LDFLAGS="-O0 -g -Werror"
make 
