/*
 * Project: udptunnel
 * File: socket.c
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
#include <string.h>
#include <sys/types.h>

#ifndef WIN32
#include <unistd.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif /*WIN32*/

#include "socket.h"
#include "common.h"

extern int debug_level;
extern int reuseaddr;
extern int reuseport;

void print_hexdump(char *data, int len);

/*
 * Allocates and returns a new socket structure.
 * host - string of host or address to listen on (can be NULL for servers)
 * port - string of port number or service (can be NULL for clients)
 * ipver - SOCK_IPV4 or SOCK_IPV6
 * sock_type - SOCK_TYPE_TCP or SOCK_TYPE_UDP
 * is_serv - 1 if is a server socket to bind and listen on port, 0 if client
 * conn - call socket(), bind(), and listen() if is_serv, or connect()
 *        if not is_serv. Doesn't call these if conn is 0.
 */
socket_t *sock_create(char *host, char *port, int ipver, int sock_type,
                      int is_serv, int conn)
{
    socket_t *sock = NULL;
    struct addrinfo hints;
    struct addrinfo *info = NULL;
    struct sockaddr *paddr;
    int ret;
    
    sock = calloc(1, sizeof(*sock));
    if(!sock)
        return NULL;

    paddr = (struct sockaddr *)&sock->addr;
    sock->fd = -1;

    switch(sock_type)
    {
        case SOCK_TYPE_TCP:
            sock->type = SOCK_STREAM;
            break;
        case SOCK_TYPE_UDP:
            sock->type = SOCK_DGRAM;
            break;
        default:
            goto error;
    }

    /* If both host and port are null, then don't create any socket or
       address */
    if(host == NULL && port == NULL)
        goto done;
    
    /* Setup type of address to get */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = (ipver == SOCK_IPV6) ? AF_INET6 : AF_INET;
    hints.ai_socktype = sock->type;
    hints.ai_flags = is_serv ? AI_PASSIVE : 0;

    /* Get address from the machine */
    ret = getaddrinfo(host, port, &hints, &info);
    PERROR_GOTO(ret != 0, "getaddrinfo", error);
    memcpy(paddr, info->ai_addr, info->ai_addrlen);
    sock->addr_len = info->ai_addrlen;

    if(conn)
    {
        if(sock_connect(sock, is_serv, port) != 0)
            goto error;
    }

  done:
    if(info)
        freeaddrinfo(info);
    
    return sock;
    
  error:
    if(sock)
        free(sock);
    if(info)
        freeaddrinfo(info);
    
    return NULL;
}

socket_t *sock_copy(socket_t *sock)
{
    socket_t *new;

    new = malloc(sizeof(*sock));
    if(!new)
        return NULL;

    memcpy(new, sock, sizeof(*sock));

    return new;
}

/*
 *
 */
int sock_connect(socket_t *sock, int is_serv, char *port)
{
    struct sockaddr *paddr;
	struct sockaddr_in sa;
    int ret;

    ERROR_GOTO(sock->fd != -1, "Socket already connected.", error);    
    paddr = SOCK_ADDR(sock);
    
    /* Create socket file descriptor */
    sock->fd = socket(paddr->sa_family, sock->type, sock->type == SOCK_DGRAM ? IPPROTO_UDP : 0);
    sock->fd = socket(PF_INET, sock->type, sock->type == SOCK_DGRAM ? IPPROTO_UDP : 0);
    PERROR_GOTO(sock->fd < 0, "socket", error);

	sa.sin_family = AF_INET;
	sa.sin_port = htons(atoi(port));
	sa.sin_addr.s_addr = htonl(INADDR_ANY);

    setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int));
    setsockopt(sock->fd, SOL_SOCKET, SO_REUSEPORT, &reuseport, sizeof(int));
 
	if(sock->type == SOCK_DGRAM)
		if( bind(sock->fd, (const struct sockaddr *)&sa, sizeof(struct sockaddr_in))!= 0)
			printf("Bind failed\n");

    if(is_serv)
    {
        /* Start listening on the port if tcp */
        if(sock->type == SOCK_STREAM)
        {
        	/* Bind socket to address and port */
        	ret = bind(sock->fd, paddr, sock->addr_len);
        	PERROR_GOTO(ret != 0, "bind", error);

            ret = listen(sock->fd, BACKLOG);
            PERROR_GOTO(ret != 0, "listen", error);
        }
    }
    else
    {
        /* Connect to the server if tcp */
        if(sock->type == SOCK_STREAM)
        {
            ret = connect(sock->fd, paddr, sock->addr_len);
            PERROR_GOTO(ret != 0, "connect", error);
        }
    }

    return 0;
    
  error:
    return -1;
}

/*
 * Accept a new connection and return a newly allocated socket representing
 * the remote connection.
 */
socket_t *sock_accept(socket_t *serv)
{
    socket_t *client;
    
    client = calloc(1, sizeof(*client));
    if(!client)
        goto error;

    client->type = serv->type;
    client->addr_len = sizeof(struct sockaddr_storage);
    client->fd = accept(serv->fd, SOCK_ADDR(client), &client->addr_len);
    PERROR_GOTO(SOCK_FD(client) < 0, "accept", error);
        
    return client;
    
  error:
    if(client)
        free(client);

    return NULL;
}

/*
 * Returns non zero if IP addresses and ports are same, or 0 if not.
 */
int sock_addr_equal(socket_t *s1, socket_t *s2)
{
    if(s1->addr_len != s2->addr_len)
        return 0;
    
    return (memcmp(&s1->addr, &s2->addr, s1->addr_len) == 0);
}

/*
 * Closes the file descriptor for the socket.
 */
void sock_close(socket_t *s)
{
    if(s->fd != -1)
    {
#ifdef WIN32
        closesocket(s->fd);
#else
        close(s->fd);
#endif
        s->fd = -1;
    }
}

/*
 * Frees the socket structure.
 */
void sock_free(socket_t *s)
{
    free(s);
}

/*
 * Gets the string representation of the IP address and port from addr. Will
 * store result in buf, which len must be at least INET6_ADDRLEN + 6. Returns a
 * pointer to buf. String will be in the form of "ip_address:port".
 */
#ifdef WIN32
char *sock_get_str(socket_t *s, char *buf, int len)
{
    /* WSAAddressToString() gets the port also, so just call get_addrstr()
       here because it will have the same output */
    return sock_get_addrstr(s, buf, len);
}
#else
char *sock_get_str(socket_t *s, char *buf, int len)
{
    void *src_addr;
    char addr_str[INET6_ADDRSTRLEN];
    unsigned short port;
    
    switch(s->addr.ss_family)
    {
        case AF_INET:
            src_addr = (void *)&((struct sockaddr_in *)&s->addr)->sin_addr;
            port = ntohs(((struct sockaddr_in *)&s->addr)->sin_port);
            break;

        case AF_INET6:
            src_addr = (void *)&((struct sockaddr_in6 *)&s->addr)->sin6_addr;
            port = ntohs(((struct sockaddr_in6 *)&s->addr)->sin6_port);
            break;
            
        default:
            return NULL;
    }

    if(inet_ntop(s->addr.ss_family, src_addr,
                 addr_str, sizeof(addr_str)) == NULL)
        return NULL;

    snprintf(buf, len, "%s:%hu", addr_str, port);
    
    return buf;
}
#endif /*WIN32*/

/*
 * Gets the string representation of the IP address and puts it in buf. Will
 * return the pointer to buf or NULL if there was an error.
 */
#ifdef WIN32
char *sock_get_addrstr(socket_t *s, char *buf, int len)
{
    DWORD plen = len;

    if(WSAAddressToString((struct sockaddr *)&s->addr, s->addr_len,
                          NULL, buf, &plen) != 0)
    {
        return NULL;
    }

    return buf;
}
#else
char *sock_get_addrstr(socket_t *s, char *buf, int len)
{
    void *src_addr;

    switch(s->addr.ss_family)
    {
        case AF_INET:
            src_addr = (void *)&((struct sockaddr_in *)&s->addr)->sin_addr;
            break;

        case AF_INET6:
            src_addr = (void *)&((struct sockaddr_in6 *)&s->addr)->sin6_addr;
            break;
            
        default:
            return NULL;
    }

    if(inet_ntop(s->addr.ss_family, src_addr, buf, len) == NULL)
        return NULL;

    return buf;
}
#endif /*WIN32*/

/*
 * Returns the 16-bit port number in host byte order from the passed sockaddr.
 */
uint16_t sock_get_port(socket_t *s)
{
    switch(s->addr.ss_family)
    {
        case AF_INET:
            return (uint16_t)ntohs(((struct sockaddr_in *)&s->addr)->sin_port);

        case AF_INET6:
            return (uint16_t)
                ntohs(((struct sockaddr_in6 *)&s->addr)->sin6_port);
    }

    return 0;
}

/*
 * Receives data from the socket. Calles recv() or recvfrom() depending on the
 * type of socket. Ignores the 'from' argument if type is for TCP, or puts
 * remove address in from socket for UDP. Reads up to len bytes and puts it in
 * data. Returns number of bytes sent, or 0 if remote host disconnected, or -1
 * on error.
 */
int sock_recv(socket_t *sock, socket_t *from, char *data, int len)
{
    int bytes_recv = 0;
    socket_t tmp;
    
    switch(sock->type)
    {
        case SOCK_STREAM:
            bytes_recv = recv(sock->fd, data, len, 0);
            break;

        case SOCK_DGRAM:
            if(!from)
                from = &tmp; /* In case caller wants to ignore from socket */
            from->fd = sock->fd;
            from->addr_len = sock->addr_len;
            bytes_recv = recvfrom(from->fd, data, len, 0,
                                  SOCK_ADDR(from), &from->addr_len);
            break;
    }
    
    PERROR_GOTO(bytes_recv < 0, "recv", error);
    ERROR_GOTO(bytes_recv == 0, "disconnect", disconnect);

    if(debug_level >= DEBUG_LEVEL3)
    {
        printf("sock_recv: type=%d, fd=%d, bytes=%d\n",
               sock->type, sock->fd, bytes_recv);
        print_hexdump(data, bytes_recv);
    }
    
    return bytes_recv;
    
  disconnect:
    return 0;
    
  error:
    return -1;
}

/*
 * Sends len bytes in data to the socket connection. Returns number of bytes
 * sent, or 0 on disconnect, or -1 on error.
 */
int sock_send(socket_t *to, char *data, int len)
{
    int bytes_sent = 0;
    int ret;
    
    switch(to->type)
    {
        case SOCK_STREAM:
            while(bytes_sent < len)
            {
                ret = send(to->fd, data + bytes_sent, len - bytes_sent, 0);
                PERROR_GOTO(ret < 0, "send", error);
                ERROR_GOTO(ret == 0, "disconnected", disconnect);
                bytes_sent += ret;
            }
            break;

        case SOCK_DGRAM:
            bytes_sent = sendto(to->fd, data, len, 0,
                                SOCK_ADDR(to), to->addr_len);
            PERROR_GOTO(bytes_sent < 0, "sendto", error);
            break;

        default:
            return 0;
    }

    if(debug_level >= DEBUG_LEVEL3)
    {
        printf("sock_send: type=%d, fd=%d, bytes=%d\n",
               to->type, to->fd, bytes_sent);
        print_hexdump(data, bytes_sent);
    }

    return bytes_sent;

  disconnect:
    return 0;
    
  error:
    return -1;
}

void print_hexdump(char *data, int len)
{
    int line;
    int max_lines = (len / 16) + (len % 16 == 0 ? 0 : 1);
    int i;
    
    for(line = 0; line < max_lines; line++)
    {
        printf("%08x  ", line * 16);

        /* print hex */
        for(i = line * 16; i < (8 + (line * 16)); i++)
        {
            if(i < len)
                printf("%02x ", (uint8_t)data[i]);
            else
                printf("   ");
        }
        printf(" ");
        for(i = (line * 16) + 8; i < (16 + (line * 16)); i++)
        {
            if(i < len)
                printf("%02x ", (uint8_t)data[i]);
            else
                printf("   ");
        }

        printf(" ");
        
        /* print ascii */
        for(i = line * 16; i < (8 + (line * 16)); i++)
        {
            if(i < len)
            {
                if(32 <= data[i] && data[i] <= 126)
                    printf("%c", data[i]);
                else
                    printf(".");
            }
            else
                printf(" ");
        }
        printf(" ");
        for(i = (line * 16) + 8; i < (16 + (line * 16)); i++)
        {
            if(i < len)
            {
                if(32 <= data[i] && data[i] <= 126)
                    printf("%c", data[i]);
                else
                    printf(".");
            }
            else
                printf(" ");
        }

        printf("\n");
    }
}
