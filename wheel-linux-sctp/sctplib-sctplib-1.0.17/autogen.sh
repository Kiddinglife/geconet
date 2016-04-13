#!/bin/sh
./bootstrap && ./configure --enable-static --disable-shared --enable-maintainer-mode --enable-sctp-over-udp $@ && make
