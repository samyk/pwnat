#
# Project: udptunnel
# File: Makefile
#
# Copyright (C) 2009 Daniel Meekins
# Contact: dmeekins - gmail
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Uncomment appropriate one for the system this is compiling for
OS=LINUX
#OS=SOLARIS
#OS=CYGWIN

CC=gcc
CFLAGS=-Wall -Wshadow -Wpointer-arith -Wwrite-strings -D ${OS}

ifeq (${OS}, SOLARIS)
LDFLAGS=-lnsl -lsocket -lresolv
endif

all: pwnat

#
# Main program
#
OBJS=src/socket.o src/message.o src/strlcpy.o src/client.o src/packet.o src/list.o src/destination.o src/udpserver.o src/udpclient.o
pwnat: src/pwnat.c ${OBJS}
	${CC} ${CFLAGS} -o pwnat src/pwnat.c ${OBJS} ${LDFLAGS}

#
# Supporting code
#
src/strlcpy.o:     src/strlcpy.c     src/common.h
	${CC} ${CFLAGS} -o $@ -c $<
src/packet.o:      src/packet.c      src/common.h src/packet.h
	${CC} ${CFLAGS} -o $@ -c $<
src/list.o:        src/list.c        src/common.h src/list.h
	${CC} ${CFLAGS} -o $@ -c $<
src/socket.o:      src/socket.c      src/common.h src/socket.h
	${CC} ${CFLAGS} -o $@ -c $<
src/client.o:      src/client.c      src/common.h src/client.h
	${CC} ${CFLAGS} -o $@ -c $<
src/message.o:     src/message.c     src/common.h src/message.h
	${CC} ${CFLAGS} -o $@ -c $<
src/destination.o: src/destination.c src/common.h src/destination.h
	${CC} ${CFLAGS} -o $@ -c $<
src/udpclient.o:   src/udpclient.c   src/common.h src/packet.h src/list.h src/socket.h src/client.h src/message.h
	${CC} ${CFLAGS} -o $@ -c $<
src/udpserver.o:   src/udpserver.c   src/common.h src/packet.h src/list.h src/socket.h src/client.h src/message.h src/destination.h
	${CC} ${CFLAGS} -o $@ -c $<

#
# Clean compiled and temporary files
#
clean:
ifeq (${OS}, CYGWIN)
	rm -f pwnat.exe
else
	rm -f pwnat
endif
	rm -f *~ src/*.o
