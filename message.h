/*
 * Project: udptunnel
 * File: message.h
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

#ifndef MESSAGE_H
#define MESSAGE_H

#ifndef WIN32
#include <inttypes.h>
#include <arpa/inet.h>
#endif /*WIN32*/

#include "common.h"
#include "socket.h"

#define MSG_MAX_LEN 1024 /* max bytes to send in body of message (16 bits) */
#define KEEP_ALIVE_SECS 60
#define KEEP_ALIVE_TIMEOUT_SECS (7*60+1) /* has 7 tries to send a keep alive */

/* Message types: max 8 bits */
#define MSG_TYPE_GOODBYE   0x01
#define MSG_TYPE_HELLO     0x02
#define MSG_TYPE_HELLOACK  0x03
#define MSG_TYPE_KEEPALIVE 0x04
#define MSG_TYPE_DATA0     0x05
#define MSG_TYPE_DATA1     0x06
#define MSG_TYPE_ACK0      0x07
#define MSG_TYPE_ACK1      0x08

#ifndef WIN32
struct msg_hdr
{
    uint16_t client_id;
    uint8_t type;
    uint16_t length;
} __attribute__ ((__packed__));
#else
#pragma pack(push, 1)
struct msg_hdr
{
    uint16_t client_id;
    uint8_t type;
    uint16_t length;
};
#pragma pack(pop)
#endif /*WIN32*/

typedef struct msg_hdr msg_hdr_t;

int msg_send_msg(socket_t *to, uint16_t client_id, uint8_t type,
                 char *data, int data_len);
int msg_send_hello(socket_t *to, char *host, char *port, uint16_t req_id);
int msg_recv_msg(socket_t *sock, socket_t *from,
                 char *data, int data_len,
                 uint16_t *client_id, uint8_t *type, uint16_t *length);

/* Inline functions for working with the message header struct */
static _inline_ void msg_init_header(msg_hdr_t *hdr, uint16_t client_id,
                                   uint8_t type, uint16_t len)
{
    hdr->client_id = htons(client_id);
    hdr->type = type;
    hdr->length = htons(len);
}

static _inline_ uint16_t msg_get_client_id(msg_hdr_t *h)
{
    return ntohs(h->client_id);
}

static _inline_ uint8_t msg_get_type(msg_hdr_t *h)
{
    return h->type;
}

static _inline_ uint16_t msg_get_length(msg_hdr_t *h)
{
    return ntohs(h->length);
}

#endif /* MESSAGE_H */
