/*
 * Project: udptunnel
 * File: client.h
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

#ifndef CLIENT_H
#define CLIENT_H

#ifndef WIN32
#include <inttypes.h>
#include <sys/time.h>
#endif /*WIN32*/

#include "common.h"
#include "socket.h"
#include "message.h"

#define CLIENT_TIMEOUT 1 /* in seconds */
#define CLIENT_MAX_RESEND 10

#define CLIENT_WAIT_HELLO 1
#define CLIENT_WAIT_DATA0 2
#define CLIENT_WAIT_DATA1 3
#define CLIENT_WAIT_ACK0  4
#define CLIENT_WAIT_ACK1  5

typedef struct client
{
    uint16_t id; /* Must be first in struct */
    socket_t *tcp_sock; /* Socket for connection to TCP server */
    socket_t *udp_sock; /* Socket to hold address from UDP client */
    int connected;
    struct timeval keepalive;

    /* For data going from UDP tunnel to TCP connection */
    char udp2tcp[MSG_MAX_LEN];
    int udp2tcp_len;
    int udp2tcp_state;

    /* For data going from TCP connection to UDP tunnel */
    char tcp2udp[MSG_MAX_LEN];
    int tcp2udp_len;
    int tcp2udp_state;
    struct timeval tcp2udp_timeout;
    int resend_count;
} client_t;

#define CLIENT_ID(c) ((c)->id)

client_t *client_create(uint16_t id, socket_t *tcp_sock, socket_t *udp_sock,
                        int connected);
client_t *client_copy(client_t *dst, client_t *src, size_t len);
int client_cmp(client_t *c1, client_t *c2, size_t len);
int client_connect_tcp(client_t *c, char *port);
void client_disconnect_tcp(client_t *c);
void client_disconnect_udp(client_t *c);
void client_free(client_t *c);
int client_recv_udp_msg(client_t *client, char *data, int data_len,
                        uint16_t *id, uint8_t *msg_type, uint16_t *len);
int client_got_udp_data(client_t *client, char *data, int data_len,
                        uint8_t msg_type);
int client_send_tcp_data(client_t *client);
int client_recv_tcp_data(client_t *client);
int client_send_udp_data(client_t *client);
int client_got_ack(client_t *client, uint8_t ack_type);
int client_send_hello(client_t *client, char *host, char *port,
                      uint16_t req_id);
int client_send_helloack(client_t *client, uint16_t req_id);
int client_got_helloack(client_t *client);
int client_send_goodbye(client_t *client);
int client_check_and_resend(client_t *client, struct timeval curr_tv);
int client_check_and_send_keepalive(client_t *client, struct timeval curr_tv);
void client_reset_keepalive(client_t *client);
int client_timed_out(client_t *client, struct timeval curr_tv);

/* Function pointers to use when making a list_t of clients */
#define p_client_copy ((void* (*)(void *, const void *, size_t))&client_copy)
#define p_client_cmp ((int (*)(const void *, const void *, size_t))&client_cmp)
#define p_client_free ((void (*)(void *))&client_free)

/* Inline functions as wrappers for handling the file descriptors in the
 * client's sockets */

static _inline_ void client_add_tcp_fd_to_set(client_t *c, fd_set *set)
{
    if(SOCK_FD(c->tcp_sock) >= 0)
        FD_SET(SOCK_FD(c->tcp_sock), set);
}

static _inline_ void client_add_udp_fd_to_set(client_t *c, fd_set *set)
{
    if(SOCK_FD(c->udp_sock) >= 0)
        FD_SET(SOCK_FD(c->udp_sock), set);
}

static _inline_ int client_tcp_fd_isset(client_t *c, fd_set *set)
{
    return SOCK_FD(c->tcp_sock) >= 0 ?
        FD_ISSET(SOCK_FD(c->tcp_sock), set) : 0;
}

static _inline_ int client_udp_fd_isset(client_t *c, fd_set *set)
{
    return SOCK_FD(c->udp_sock) >= 0 ?
        FD_ISSET(SOCK_FD(c->udp_sock), set) : 0;
    
}

static _inline_ void client_remove_tcp_fd_from_set(client_t *c, fd_set *set)
{
    if(SOCK_FD(c->tcp_sock) >= 0)
        FD_CLR(SOCK_FD(c->tcp_sock), set);
}

static _inline_ void client_remove_udp_fd_from_set(client_t *c, fd_set *set)
{
    if(SOCK_FD(c->udp_sock) >= 0)
        FD_CLR(SOCK_FD(c->udp_sock), set);
}

#endif /* CLIENT_H */
