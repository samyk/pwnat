/*
 * Project: udptunnel
 * File: common.h
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

#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <sys/types.h>

#ifdef WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
    WINSOCK_API_LINKAGE const char WSAAPI inet_ntop(int af, const void src, char *dst, socklen_t size);
    WINSOCK_API_LINKAGE int WSAAPI inet_pton(int af, const char* src, void *dst);
    typedef unsigned char	    u_int8_t;
    typedef unsigned short	    u_int16_t;

#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#endif

#include <limits.h>


#define NO_DEBUG     0
#define DEBUG_LEVEL1 1
#define DEBUG_LEVEL2 2
#define DEBUG_LEVEL3 3

extern int opt_debug;
extern struct sockaddr_in remote;

#ifdef WIN32
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
#endif

/* cl.exe has a different 'inline' keyword for some dumb reason */
#ifdef WIN32
#define _inline_ __inline
#else
#define _inline_ inline
#endif

#define PERROR_GOTO(cond,err,label){        \
        if(cond)                            \
        {                                   \
                perror(err) ;               \
            goto label;                     \
        }}

            //if(debug_level >= DEBUG_LEVEL1)

#define ERROR_GOTO(cond,str,label){                  \
        if(cond)                                     \
        {                                            \
            if(debug_level >= DEBUG_LEVEL2)          \
                fprintf(stderr, "Error: %s\n", str); \
            goto label;                              \
        }}

#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

#ifdef SOLARIS
/* Copied from sys/time.h on linux system since solaris system that tried to
 * compile on didn't have timeradd macro. */
#define timeradd(a, b, result)                                                \
    do {                                                                      \
        (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;                         \
        (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;                      \
        if ((result)->tv_usec >= 1000000)                                     \
        {                                                                     \
            ++(result)->tv_sec;                                               \
            (result)->tv_usec -= 1000000;                                     \
        }                                                                     \
    } while (0)
#endif /* SOLARIS */

#ifdef WIN32
#define timeradd(a, b, result)                                                \
    do {                                                                      \
        (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;                         \
        (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;                      \
        if ((result)->tv_usec >= 1000000)                                     \
        {                                                                     \
            ++(result)->tv_sec;                                               \
            (result)->tv_usec -= 1000000;                                     \
        }                                                                     \
    } while (0)
#endif

#endif /* COMMON_H */
