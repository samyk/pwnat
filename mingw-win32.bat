@echo off
where gcc
if %ERRORLEVEL% NEQ 0 (
    echo "No find gcc(gcc should be in PATH)"
) else (
    set OS=_WIN32
    set CC=gcc
    set CFLAGS=-Wall -Wshadow -Wpointer-arith -Wwrite-strings -D %OS%
    set LDFLAGS=

    set LIBS= -L "C:\Program Files (x86)\Windows Kits\1o\Lib\1o.o.22621.o\um\x86" -lws2_32

    set OBJS=o\socket.o o\message.o o\strlcpy.o o\client.o o\packet.o o\list.o o\destination.o o\udpserver.o o\udpclient.o o/xgetopt.o o/gettimeofday.o

    mkdir o

    %CC% %CFLAGS% -o o\strlcpy.o -c src\strlcpy.c

    %CC% %CFLAGS% -o o\packet.o -c src\packet.c

    %CC% %CFLAGS% -o o\list.o -c src\list.c

    %CC% %CFLAGS% -o o\socket.o -c src\socket.c

    %CC% %CFLAGS% -o o\client.o -c src\client.c

    %CC% %CFLAGS% -o o\message.o -c src\message.c

    %CC% %CFLAGS% -o o\destination.o -c src\destination.c

    %CC% %CFLAGS% -o o\udpclient.o -c src\udpclient.c

    %CC% %CFLAGS% -o o\udpserver.o -c src\udpserver.c

    %CC% %CFLAGS% -o o\xgetopt.o -c src\xgetopt.c

    %CC% %CFLAGS% -o o\gettimeofday.o -c src\gettimeofday.c


    %CC% %CFLAGS% -o pwnat.exe src\pwnat.c %OBJS% %LDFLAGS% %LIBS%
)