/*
 * pwnat, by Samy Kamkar
 * based off of udptunnel
 *
 * udptunnel original comments:
 *
 * Copyright (C) 2009 Daniel Meekins
 * Contact: dmeekins - gmail
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>

#ifndef WIN32
#include <unistd.h>
#else
#include "xgetopt.h"
#endif

#include "common.h"
#include "socket.h"

int opt_debug = 0;
struct sockaddr_in remote;

int debug_level = 1; //NO_DEBUG;
int ipver = SOCK_IPV4;

int reuseaddr = 0;
int reuseport = 0;

int udpclient(int argc, char *argv[]);
int udpserver(int argc, char *argv[]);
void usage(char *progname);

int main(int argc, char *argv[])
{
    int ret;
    int isserv = 0;

#ifdef WIN32    
    WSADATA wsa_data;
    ret = WSAStartup(MAKEWORD(2,0), &wsa_data);
    ERROR_GOTO(ret != 0, "WSAStartup() failed", error);
#endif
    
    while((ret = getopt(argc, argv, "hscv6ap")) != EOF)
    {
        switch(ret)
        {
            case '6':
                ipver = SOCK_IPV6;
                break;
                
            case 's':
                isserv = 1;
                break;
                
            case 'c':
                isserv = 0;
                break;

            case 'a':
                reuseaddr = 1;
                break;

            case 'p':
                reuseport = 1;
                break;

            case 'v':
                if(debug_level < 3)
                    debug_level++;
                break;
                
            case 'h':
                /* fall through */
            default:
                goto error;
        }
    }

    ret = 0;
    
    if(isserv)
    {
        if(argc - optind < 0)
            goto error;
        ret = udpserver(argc - optind, argv + optind);
    }
    else
    {
        if(argc - optind != 5 && argc - optind != 6 && argc - optind != 4)
            goto error;
        ret = udpclient(argc - optind, argv + optind);
    }

#ifdef WIN32
    WSACleanup();
#endif
    
    return ret;
    
  error:
    usage(argv[0]);
    exit(1);
}

void usage(char *progname)
{
    printf("usage: %s <-s | -c> <args>\n", progname);
    printf("  -c    client mode (default)\n"
           "        <args>: [local ip] <local port> <proxy host> [proxy port (def:2222)] <remote host> <remote port>\n"
           "  -s    server mode\n"
           "        <args>: [local ip] [proxy port (def:2222)] [[allowed host]:[allowed port] ...]\n"
           "  -6    use IPv6\n"
           "  -v    show debug output (up to 2)\n"
           "  -a    reuse address\n"
           "  -p    reuse port\n"
           "  -h    show this help and exit\n");
}
