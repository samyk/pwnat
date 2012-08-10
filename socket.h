/*
 * Project: udptunnel
 * File: socket.h
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

#ifndef SOCKET_H
#define SOCKET_H

#ifndef WIN32
#include <inttypes.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif /*WIN32*/

#include "common.h"

#define BACKLOG 10
#define ADDRSTRLEN (INET6_ADDRSTRLEN + 7)

#define SOCK_TYPE_TCP 1
#define SOCK_TYPE_UDP 2
#define SOCK_IPV4     3
#define SOCK_IPV6     4

#define SIN(sa) ((struct sockaddr_in *)sa)
#define SIN6(sa) ((struct sockaddr_in6 *)sa)

typedef struct socket {
    int fd;                       /* Socket file descriptor to send/recv on */
    int type;                     /* SOCK_STREAM or SOCK_DGRAM */
    struct sockaddr_storage addr; /* IP and port */
    socklen_t addr_len;           /* Length of sockaddr type */
} socket_t;

#define SOCK_FD(s) ((s)->fd)
#define SOCK_LEN(s) ((s)->addr_len)
#define SOCK_ADDR(s) ((struct sockaddr *)&(s)->addr)

socket_t *sock_create(char *host, char *port, int ipver, int sock_type,
                      int is_serv, int conn);
socket_t *sock_copy(socket_t *sock);
int sock_connect(socket_t *sock, int is_serv, char *port);
socket_t *sock_accept(socket_t *serv);
int sock_addr_equal(socket_t *s1, socket_t *s2);
void sock_close(socket_t *s);
void sock_free(socket_t *s);

char *sock_get_str(socket_t *s, char *buf, int len);
char *sock_get_addrstr(socket_t *s, char *buf, int len);
uint16_t sock_get_port(socket_t *s);
int sock_recv(socket_t *sock, socket_t *from, char *data, int len);
int sock_send(socket_t *to, char *data, int len);

#endif /* SOCKET_H */
