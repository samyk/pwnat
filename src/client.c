/*
 * Project: udptunnel
 * File: client.c
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
#include <sys/time.h>
#endif /*WIN32*/

#include "common.h"
#include "client.h"
#include "socket.h"

extern int debug_level;

/*
 * Allocates and initializes a new client object.
 * id - ID number for the client to have
 * tcp_sock/udp_sock - sockets attributed to the client. this function copies
 *   the structure, so the calling function can free the sockets passed to
 *   here.
 * connected - whether the TCP socket is connected or not.
 * Returns a pointer to the new structure. Call client_free() when done with
 * it.
 */
client_t *client_create(uint16_t id, socket_t *tcp_sock, socket_t *udp_sock,
                        int connected)
{
    client_t *c = NULL;

    c = calloc(1, sizeof(client_t));
    if(!c)
        goto error;
    
    c->id = id;
    c->tcp_sock = sock_copy(tcp_sock);
    c->udp_sock = sock_copy(udp_sock);
    c->udp2tcp_state = CLIENT_WAIT_HELLO;
    c->tcp2udp_state = CLIENT_WAIT_DATA0;
    c->connected = connected;

    timerclear(&c->keepalive);
    timerclear(&c->tcp2udp_timeout);
    c->resend_count = 0;

    return c;
    
  error:
    if(c)
    {
        if(c->tcp_sock)
            sock_free(c->tcp_sock);
        if(c->udp_sock)
            sock_free(c->udp_sock);
        free(c);
    }

    return NULL;
}

/*
 * Performs a deep copy of the client structure.
 */
client_t *client_copy(client_t *dst, client_t *src, size_t len)
{
    if(!dst || !src)
        return NULL;

    memcpy(dst, src, sizeof(*src));

    dst->tcp_sock = sock_copy(src->tcp_sock);
    if(!dst->tcp_sock)
        return NULL;

    dst->udp_sock = sock_copy(src->udp_sock);
    if(!dst->udp_sock)
        return NULL;

    return dst;
}

/*
 * Compares the ID of the two clients.
 */
int client_cmp(client_t *c1, client_t *c2, size_t len)
{
    return c1->id - c2->id;
}

/*
 * Connects the TCP socket of the client (wrapper for sock_connect()). Returns
 * 0 on success or -1 on error.
 */
int client_connect_tcp(client_t *c, char *port)
{
    if(!c->connected)
    {
        if(sock_connect(c->tcp_sock, 0, port) == 0)
        {
            c->connected = 1;
            return 0;
        }
    }

    return -1;
}

/*
 * Closes the TCP socket for the client (wrapper for sock_close()).
 */
void client_disconnect_tcp(client_t *c)
{
    if(c->connected)
    {
        sock_close(c->tcp_sock);
        c->connected = 0;
    }
}

/*
 * Closes the UDP socket for the client (wrapper for sock_close()).
 */
void client_disconnect_udp(client_t *c)
{
    sock_close(c->udp_sock);    
}

/*
 * Releases the memory used by the client.
 */
void client_free(client_t *c)
{
    if(c)
    {
        sock_free(c->tcp_sock);
        sock_free(c->udp_sock);
        free(c);
    }
}

/*
 * Receives a message from the UDP tunnel for the client. Only used in
 * udpclient program because each client has their own UDP socket. Returns 0
 * for success or -1 on error. The data is written to memory pointed to by
 * data, and the id, msg_type, and len are set from the message header.
 */
int client_recv_udp_msg(client_t *client, char *data, int data_len,
                        uint16_t *id, uint8_t *msg_type, uint16_t *len)
{
    int ret;
    socket_t from;

    ret = msg_recv_msg(client->udp_sock, &from, data, data_len,
                       id, msg_type, len);
    if(ret < 0)
        return ret;

    if(!sock_addr_equal(client->udp_sock, &from))
        return -1;

    return 0;
}

/*
 * Copy data to the internal buffer for sending to tcp connection and send ACK
 * back to tunnel. Returns 0 on success, 1 if this was "resending" data, -1
 * on error, or -2 if need to disconnect.
 */
int client_got_udp_data(client_t *client, char *data, int data_len,
                        uint8_t msg_type)
{
    int ret;
    int is_resend = 0;

    if(data_len > MSG_MAX_LEN)
        return -1;

    /* Check if got new data, which is when got the data type (DATA0 or DATA1)
       that it was waiting for, and write that new data to the buffer. */
    if((msg_type == MSG_TYPE_DATA0 &&
        client->udp2tcp_state == CLIENT_WAIT_DATA0)
       || (msg_type == MSG_TYPE_DATA1 &&
           client->udp2tcp_state == CLIENT_WAIT_DATA1))
    {
        memcpy(client->udp2tcp, data, data_len);
        client->udp2tcp_len = data_len;
    }
    else
        is_resend = 1; /* Otherwise, the other host resent the data */

    msg_type = (msg_type == MSG_TYPE_DATA0) ? MSG_TYPE_ACK0 : MSG_TYPE_ACK1;

    /* Send the ACK for the data */
    ret = msg_send_msg(client->udp_sock, client->id, msg_type, NULL, 0);
    if(ret < 0)
        return ret;
    
    if(is_resend)
        return 1;
    
    /* Set the state to wait for the next type of data */
    client->udp2tcp_state = client->udp2tcp_state == CLIENT_WAIT_DATA0 ?
        CLIENT_WAIT_DATA1 : CLIENT_WAIT_DATA0;
    
    return 0;
}

/*
 * Send data received from UDP tunnel to TCP connection. Need to call
 * client_got_udp_data() first. Returns -1 on general error, -2 if need to
 * disconnect, and 0 on success.
 */
int client_send_tcp_data(client_t *client)
{
    int ret;
    
    ret = sock_send(client->tcp_sock, client->udp2tcp, client->udp2tcp_len);

    if(ret < 0)
        return -1;
    else if(ret == 0)
        return -2;
    else    
        return 0;
}

/*
 * Reads data that is ready on the TCP socket and stores it in the internal
 * buffer. The routine client_send_udp_data() send that data to the tunnel.
 */
int client_recv_tcp_data(client_t *client)
{
    int ret;

    /* Don't read the tcp data yet if waiting for an ack or the hello */
    if(client->tcp2udp_state == CLIENT_WAIT_ACK0 ||
       client->tcp2udp_state == CLIENT_WAIT_ACK1 ||
       client->udp2tcp_state == CLIENT_WAIT_HELLO)
        return 1;
    
    ret = sock_recv(client->tcp_sock, NULL, client->tcp2udp,
                    sizeof(client->tcp2udp));
    if(ret < 0)
        return -1;
    if(ret == 0)
        return -2;

    client->tcp2udp_len = ret;

    return 0;
}

/*
 * Sends the data in the tcp2udp buffer to the UDP tunnel. Returns 0 for
 * success, -1 on error, and -2 if needs to disconnect.
 */
int client_send_udp_data(client_t *client)
{
    uint8_t msg_type;
    int ret;

    if(client->resend_count >= CLIENT_MAX_RESEND)
        return -2;

    /* Set the message type it is sending. If the client is in the WAIT_ACK
       state, then it will send the same type of data again (since this would
       have been called b/c of a timeout. */
    switch(client->tcp2udp_state)
    {
        case CLIENT_WAIT_DATA0:
        case CLIENT_WAIT_ACK0:
            msg_type = MSG_TYPE_DATA0;
            break;
            
        case CLIENT_WAIT_DATA1:
        case CLIENT_WAIT_ACK1:
            msg_type = MSG_TYPE_DATA1;
            break;

        default:
            return -1;
    }
    
    ret = msg_send_msg(client->udp_sock, client->id, msg_type,
                       client->tcp2udp, client->tcp2udp_len);
    if(ret < 0)
        return ret;

    /* Set the state to wait for an ACK and set the timeout to some time in
       the future */
    client->tcp2udp_state = (msg_type == MSG_TYPE_DATA0) ?
        CLIENT_WAIT_ACK0 : CLIENT_WAIT_ACK1;
    gettimeofday(&client->tcp2udp_timeout, NULL);
    client->tcp2udp_timeout.tv_sec += (client->resend_count+1)*CLIENT_TIMEOUT;
    
    return 0;
}

/*
 * Notifies the client that it got an ACK to change the internal state to
 * wait for data. Returns 0 if ok or -1 if something weird happened.
 */
int client_got_ack(client_t *client, uint8_t ack_type)
{
    if(ack_type == MSG_TYPE_ACK0 && client->tcp2udp_state == CLIENT_WAIT_ACK0)
    {
        client->tcp2udp_state = CLIENT_WAIT_DATA1;
        client->resend_count = 0;
        return 0;
    }

    if(ack_type == MSG_TYPE_ACK1 && client->tcp2udp_state == CLIENT_WAIT_ACK1)
    {
        client->tcp2udp_state = CLIENT_WAIT_DATA0;
        client->resend_count = 0;
        return 0;
    }

    return -1;
}

/*
 * Sends a HELLO type message to the udpserver (proxy) to tell it to make a
 * TCP connection to the specified host:port.
 */
int client_send_hello(client_t *client, char *host, char *port,
                      uint16_t req_id)
{
    return msg_send_hello(client->udp_sock, host, port, req_id);
}

/*
 * Sends a Hello ACK to the UDP tunnel.
 */
int client_send_helloack(client_t *client, uint16_t req_id)
{
    req_id = htons(req_id);

    return msg_send_msg(client->udp_sock, client->id, MSG_TYPE_HELLOACK,
                        (char *)&req_id, sizeof(req_id));
}

/*
 * Notify the client that it got a Hello ACK.
 */
int client_got_helloack(client_t *client)
{
    if(client->udp2tcp_state == CLIENT_WAIT_HELLO)
        client->udp2tcp_state = CLIENT_WAIT_DATA0;

    return 0;
}

/*
 * Sends a goodbye message to the UDP server.
 */
int client_send_goodbye(client_t *client)
{
    return msg_send_msg(client->udp_sock, client->id, MSG_TYPE_GOODBYE,
                        NULL, 0);
}

/*
 * Checks the timeout state of the client and resend the data if the timeout
 * is up.
 */
int client_check_and_resend(client_t *client, struct timeval curr_tv)
{
    if((client->tcp2udp_state == CLIENT_WAIT_ACK0 ||
        client->tcp2udp_state == CLIENT_WAIT_ACK1)
       && timercmp(&curr_tv, &client->tcp2udp_timeout, >))
    {
        client->resend_count++;
        if(debug_level >= DEBUG_LEVEL2)
            printf("client(%d): resending data, count %d\n",
                   CLIENT_ID(client), client->resend_count);
        
        return client_send_udp_data(client);
    }

    return 0;
}

/*
 * Sends a keepalive message to the UDP server.
 */
int client_check_and_send_keepalive(client_t *client, struct timeval curr_tv)
{
    if(client_timed_out(client, curr_tv))
    {
        curr_tv.tv_sec += KEEP_ALIVE_SECS;
        memcpy(&client->keepalive, &curr_tv, sizeof(struct timeval));

        return msg_send_msg(client->udp_sock, client->id, MSG_TYPE_KEEPALIVE,
                            NULL, 0);
    }

    return 0;
}

/*
 * Sets the client's keepalive timeout to be the current time plus the timeout
 * period.
 */
void client_reset_keepalive(client_t *client)
{
    struct timeval curr;

    gettimeofday(&curr, NULL);
    curr.tv_sec += KEEP_ALIVE_TIMEOUT_SECS;
    memcpy(&client->keepalive, &curr, sizeof(struct timeval));
}

/*
 * Returns 1 if the client timed out (didn't get any data or keep alive
 * messages in the period), or 0 if it hasn't yet.
 */
int client_timed_out(client_t *client, struct timeval curr_tv)
{
    if(timercmp(&curr_tv, &client->keepalive, >))
        return 1;
    else
        return 0;
}
