i686-w64-mingw32-gcc -o pwnat.exe -O3 -DWIN32 socket.c message.c strlcpy.c client.c packet.c list.c udpserver.c udpclient.c pwnat.c destination.c -lws2_32 
