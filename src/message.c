/*
 * Project: udptunnel
 * File: message.c
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

#include <stdlib.h>
#include <string.h>

#ifndef WIN32
#include <sys/types.h>
#include <sys/socket.h>
#endif /*WIN32*/

#include "common.h"
#include "message.h"
#include "socket.h"

/*
 * Sends a message to the UDP tunnel with the specified client ID, type, and
 * data. The data can be NULL and data_len 0 if the type of message won't have
 * a body, based on the protocol.
 * Returns 0 for success, -1 on error, or -2 to close the connection.
 */
int msg_send_msg(socket_t *to, uint16_t client_id, uint8_t type,
                 char *data, int data_len)
{
    char buf[MSG_MAX_LEN + sizeof(msg_hdr_t)];
    int len; /* length for entire packet */
    //uint16_t tmp_id;

    if(data_len > MSG_MAX_LEN)
        return -1;
    
    switch(type)
    {
        case MSG_TYPE_HELLO:
        case MSG_TYPE_HELLOACK:
        case MSG_TYPE_DATA0:
        case MSG_TYPE_DATA1:
            memcpy(buf+sizeof(msg_hdr_t), data, data_len);
            break;

        case MSG_TYPE_GOODBYE:
        case MSG_TYPE_KEEPALIVE:
        case MSG_TYPE_ACK0:
        case MSG_TYPE_ACK1:
            data_len = 0;
            break;
            
        default:
            return -1;
    }

    len = data_len + sizeof(msg_hdr_t);
    msg_init_header((msg_hdr_t *)buf, client_id, type, data_len);

    len = sock_send(to, buf, len);
    if(len < 0)
        return -1;
    else if(len == 0)
        return -2;
    else
        return 0;
}

/*
 * Sends a HELLO type message to the UDP tunnel with the specified host and
 * port in the body.
 * Returns 0 for success, -1 on error, or -2 to disconnect.
 */
int msg_send_hello(socket_t *to, char *host, char *port, uint16_t req_id)
{
    char *data;
    int str_len;
    int len;

    str_len = strlen(host) + strlen(port) + 2;
    len = str_len + sizeof(req_id);

    data = malloc(len);
    if(!data)
        return -1;

    *((uint16_t *)data) = htons(req_id);

#ifdef WIN32
    _snprintf(data + sizeof(req_id), str_len, "%s %s", host, port);
#else
    snprintf(data + sizeof(req_id), str_len, "%s %s", host, port);
#endif

    len = msg_send_msg(to, 0, MSG_TYPE_HELLO, data, len-1);
    free(data);

    if(len < 0)
        return -1;
    else if(len == 0)
        return -2;
    else
        return 0;
}

/*
 * Receives a message that is ready to be read from the UDP socket. Writes the
 * body of the message into data, and sets the client ID, type, and length
 * of the message.
 * Returns 0 for success, -1 on error, or -2 to disconnect.
 */
int msg_recv_msg(socket_t *sock, socket_t *from, char *data, int data_len,
                 uint16_t *client_id, uint8_t *type, uint16_t *length)
{
    char buf[MSG_MAX_LEN + sizeof(msg_hdr_t)];
    msg_hdr_t *hdr_ptr;
    char *msg_ptr;
    int ret;

    hdr_ptr = (msg_hdr_t *)buf;
    msg_ptr = buf + sizeof(msg_hdr_t);
    
    ret = sock_recv(sock, from, buf, sizeof(buf));
    if(ret < 0)
        return -1;
    else if(ret == 0)
        return -2;

    *client_id = msg_get_client_id(hdr_ptr);
    *type = msg_get_type(hdr_ptr);
    *length = msg_get_length(hdr_ptr);
    
    if(ret-sizeof(msg_hdr_t) != *length)
        return -1;

    *length = MIN(data_len, *length);
    memcpy(data, msg_ptr, *length);

    return 0;
}
