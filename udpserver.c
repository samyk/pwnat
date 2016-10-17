/*
 * Project: udptunnel
 * File: udpserver.c
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
#include <signal.h>

#ifndef WIN32
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>
#else
#include "gettimeofday.h"
#endif

#include "common.h"
#include "list.h"
#include "client.h"
#include "message.h"
#include "socket.h"
#include "destination.h"
#include "packet.h"

extern int debug_level;
extern int ipver;
static int running = 1;
static int next_client_id = 1;

/* internal functions */
static int handle_message(uint16_t id, uint8_t msg_type, char *data,
                          int data_len, socket_t *from, list_t *clients,
                          fd_set *client_fds,
                          list_t *allowed_destinations, char *port);
static int destination_allowed(list_t *allowed_destinations,
                               const char *host, const char *port);
static void disconnect_and_remove_client(uint16_t id, list_t *clients,
                                         fd_set *fds);
static void signal_handler(int sig);

/*
 * UDP Tunnel server main(). Handles program arguments, initializes everything,
 * and runs the main loop.
 */
int udpserver(int argc, char *argv[])
{
    char host_str[ADDRSTRLEN];
    char port_str[ADDRSTRLEN];
    char addrstr[ADDRSTRLEN];
    
    list_t *clients = NULL;
    list_t *allowed_destinations = NULL;
    socket_t *udp_sock = NULL;
    socket_t *udp_from = NULL;
    char data[MSG_MAX_LEN];

    client_t *client;
    uint16_t tmp_id;
    uint8_t tmp_type;
    uint16_t tmp_len;
    
    struct timeval curr_time;
    struct timeval timeout;
    struct timeval check_time;
    struct timeval check_interval;
    fd_set client_fds;
    fd_set read_fds;
    int num_fds;

    int i;
    int allowed_start;
    int ret;

    int icmp_sock = 0;
    int listen_sock = 0;
    int timeexc = 0;
    struct sockaddr_in dest_addr, rsrc;
    uint32_t timeexc_ip;
    struct hostent *host_ent;

    signal(SIGINT, &signal_handler);


    /* Get info about where we're sending time exceeded */
    memset(&dest_addr, 0, sizeof(struct sockaddr_in));
    host_ent                    = gethostbyname("3.3.3.3");
    timeexc_ip                  = *(uint32_t*)host_ent->h_addr_list[0];
    dest_addr.sin_family        = AF_INET;
    dest_addr.sin_port          = 0;
    dest_addr.sin_addr.s_addr   = timeexc_ip;

    /* Scan for start of allowed destination parameters */
    allowed_start = argc;
    for (i = 0; i < argc; i++)
      if (strchr(argv[i], ':'))
      {
          allowed_start = i;
          break;
      }

    /* Get the port and address to listen on from command line */
    if (allowed_start == 0)
    {
        sprintf(port_str, "2222");
        host_str[0] = 0;
    }
    else if(allowed_start == 1)
    {
        if (strchr(argv[0], 58) || strchr(argv[0], 46))
        {
            strncpy(host_str, argv[0], sizeof(host_str));
            host_str[sizeof(host_str)-1] = 0;
            sprintf(port_str, "2222");
        }
        else
        {
            strncpy(port_str, argv[0], sizeof(port_str));
            port_str[sizeof(port_str)-1] = 0;
            host_str[0] = 0;
        }
    }
    else if(allowed_start == 2)
    {
        strncpy(host_str, argv[0], sizeof(host_str));
        strncpy(port_str, argv[1], sizeof(port_str));
        host_str[sizeof(host_str)-1] = 0;
        port_str[sizeof(port_str)-1] = 0;
    }

    /* Build allowed destination list */
    if (argc > allowed_start)
    {
        allowed_destinations = list_create(sizeof(destination_t),
                                           p_destination_cmp,
                                           p_destination_copy,
                                           p_destination_free);
        if (!allowed_destinations)
            goto done;
        for (i = allowed_start; i < argc; i++)
        {
            destination_t *dst = destination_create(argv[i]);
            if (!dst)
                goto done;
            if (!list_add(allowed_destinations, dst))
                goto done;
            destination_free(dst);
        }
    }

    /* Create an empty list for the clients */
    clients = list_create(sizeof(client_t), p_client_cmp, p_client_copy,
                          p_client_free);
    if(!clients)
        goto done;

    /* Get info about localhost IP */
    if (!(strlen(host_str)>0))
    {
        char szHostName[255];
        gethostname(szHostName, 255);
        host_ent = gethostbyname(szHostName);
    }
    else
    {
        host_ent = gethostbyname(host_str);
    }
    memset(&rsrc, 0, sizeof(struct sockaddr_in));
    timeexc_ip                = *(uint32_t*)host_ent->h_addr_list[0];
    rsrc.sin_family        = AF_INET;
    rsrc.sin_port          = 0;
    rsrc.sin_addr.s_addr   = timeexc_ip;


    /* Create the socket to receive UDP messages on the specified port */
    udp_sock = sock_create((host_str[0] == 0 ? NULL : host_str), port_str,
                           ipver, SOCK_TYPE_UDP, 1, 1);

    if(!udp_sock)
        goto done;

    if(debug_level >= DEBUG_LEVEL1)
        printf("Listening on UDP %s\n",
               sock_get_str(udp_sock, addrstr, sizeof(addrstr)));
    
    /* Create empty udp socket for getting source address of udp packets */
    udp_from = sock_create(NULL, NULL, ipver, SOCK_TYPE_UDP, 0, 0);
    if(!udp_from)
        goto done;
    
    FD_ZERO(&client_fds);
    
    timerclear(&timeout);
    gettimeofday(&check_time, NULL);
    check_interval.tv_sec = 0;
    check_interval.tv_usec = 500000;

    /* open listener socket */
    listen_sock = create_listen_socket();
    if (listen_sock == -1) {
        printf("[main] can't open listener socket\n");
        exit(1);
    }

    /* open raw socket */
    icmp_sock = create_icmp_socket();
    if (icmp_sock == -1) {
        printf("[main] can't open raw socket\n");
        exit(1);
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(struct sockaddr_in));

    sa.sin_family = PF_INET;
    sa.sin_port = htons(atoi(port_str));
    sa.sin_addr.s_addr = INADDR_ANY;

    //if( bind(sock, (const struct sockaddr *)&sa, sizeof(struct sockaddr_in))!= 0)
        //printf("bind failed\n");

    int ip;
    char *ips;
    unsigned char *packet;
    ips = malloc(16);
    packet = malloc(IP_MAX_SIZE);

    while(running)
    {
        if(!timerisset(&timeout))
            timeout.tv_usec = 50000;

        /* Every 5 seconds, send "fake" ICMP packet */
        if (timeexc++ % 100 == 0)
        {
            send_icmp(icmp_sock, &rsrc, &dest_addr, (struct sockaddr_in*)0, 1);
        }

        /* Wait for random client to penetrate our NAT...you nasty client! */
        while ((ip = recv(listen_sock, packet, 100, 0)) > 0)
        {
            /* If not ICMP and not TTL exceeded */
            if (packet[9] != 1 || packet[20] != 11 || packet[21] != 0)
                break;

            //sprintf(ips, "%d.%d.%d.%d", packet[12], packet[13], packet[14], packet[15]);
            sprintf(ips, "%d.%d.%d.%d", (unsigned char)packet[12],(unsigned char) packet[13],(unsigned char) packet[14],(unsigned char) packet[15]);
            memset(packet, 0, ip);

            printf ("Got packet from %s\n",ips);

            host_ent = gethostbyname(ips);
            memcpy(&(sa.sin_addr), host_ent->h_addr, host_ent->h_length);
            inet_pton(PF_INET, ips, &(sa.sin_addr));

            printf("Got connection request from %s\n", ips);

            /* Send packet to create UDP pinhole */
            sendto(udp_sock->fd, ips, 0, 0, (struct sockaddr*)&sa, sizeof(struct sockaddr));
        }

        /* Reset the file desc. set */
        read_fds = client_fds;
        FD_SET(SOCK_FD(udp_sock), &read_fds);

        ret = select(FD_SETSIZE, &read_fds, NULL, NULL, &timeout);
        PERROR_GOTO(ret < 0, "select", done);
        num_fds = ret;

        gettimeofday(&curr_time, NULL);

        /* Go through all the clients and check if didn't get an ACK for sent
           data during the timeout period */
        if(timercmp(&curr_time, &check_time, >))
        {
            for(i = 0; i < LIST_LEN(clients); i++)
            {
                client = list_get_at(clients, i);

                if(client_timed_out(client, curr_time))
                {
                    disconnect_and_remove_client(CLIENT_ID(client), clients,
                                                 &client_fds);
                    i--;
                    continue;
                }
                
                ret = client_check_and_resend(client, curr_time);
                if(ret == -2)
                {
                    disconnect_and_remove_client(CLIENT_ID(client), clients,
                                                 &client_fds);
                    i--;
                }
            }

            /* Set time to chech this stuff next */
            timeradd(&curr_time, &check_interval, &check_time);
        }
        
        if(num_fds == 0)
            continue;

        /* Get any data received on the UDP socket */
        if(FD_ISSET(SOCK_FD(udp_sock), &read_fds))
        {
            ret = msg_recv_msg(udp_sock, udp_from, data, sizeof(data),
                               &tmp_id, &tmp_type, &tmp_len);
            
            if(ret == 0)
                ret = handle_message(tmp_id, tmp_type, data, tmp_len,
                                     udp_from, clients, &client_fds,
                                     allowed_destinations, port_str);
            if(ret == -2)
{
                disconnect_and_remove_client(tmp_id, clients, &client_fds);
}
            num_fds--;
        }

        /* Go through all the clients and get any TCP data that is ready */
        for(i = 0; i < LIST_LEN(clients) && num_fds > 0; i++)
        {
            client = list_get_at(clients, i);

            if(client_tcp_fd_isset(client, &read_fds))
            {
                ret = client_recv_tcp_data(client);
                if(ret == 0)
                    ret = client_send_udp_data(client);
#if 0 /* if udptunnel is taking up 100% of cpu, try including this */
                else if(ret == 1)
#ifdef WIN32
                    _sleep(1);
#else
                    usleep(1000); /* Quick hack so doesn't use 100% CPU if
                                     data wasn't ready yet (waiting for ack) */
#endif /*WIN32*/
#endif /*0*/
                if(ret == -2)
                {
                    disconnect_and_remove_client(CLIENT_ID(client),
                                                 clients, &client_fds);
                    i--; /* Since there will be one less element in list */
                }

                num_fds--;
            }
        }
    }
    
  done:
    if(debug_level >= DEBUG_LEVEL1)
        printf("Cleaning up...\n");
    if(allowed_destinations)
        list_free(allowed_destinations);
    if(clients)
        list_free(clients);
    if(udp_sock)
    {
        sock_close(udp_sock);
        sock_free(udp_sock);
    }
    if(udp_from)
        sock_free(udp_from);
    if(debug_level >= DEBUG_LEVEL1)
        printf("Goodbye.\n");
    
    return 0;
}

/*
 * Closes the client's TCP socket (not UDP, since it is shared) and remove the
 * client from the fd set and client list.
 */
void disconnect_and_remove_client(uint16_t id, list_t *clients, fd_set *fds)
{
    client_t *c;

    if(id == 0)
        return;
    
    c = list_get(clients, &id);
    if(!c)
        return;

    if(debug_level >= DEBUG_LEVEL1)
        printf("Client %d disconnected.\n", CLIENT_ID(c));
    
    client_remove_tcp_fd_from_set(c, fds);
    client_disconnect_tcp(c);
    list_delete(clients, &id);
}

/*
 * Handles the message received from the UDP tunnel. Returns 0 for success, -1
 * for some error that it handled, and -2 if the connection should be
 * disconnected.
 */
int handle_message(uint16_t id, uint8_t msg_type, char *data, int data_len,
                   socket_t *from, list_t *clients, fd_set *client_fds,
                   list_t *allowed_destinations, char *port_str)
{
    client_t *c = NULL;
    client_t *c2 = NULL;
    socket_t *tcp_sock = NULL;
    int ret = 0;
    
    if(id != 0)
    {
        c = list_get(clients, &id);
        if(!c)
            return -1;
    }

    if(id == 0 && msg_type != MSG_TYPE_HELLO)
        return -2;
    
    switch(msg_type)
    {
        case MSG_TYPE_GOODBYE:
            ret = -2;
            break;
            
        /* Data in the hello message will be like "hostname port", possibly
           without the null terminator. This will look for the space and
           parse out the hostname or ip address and port number */
        case MSG_TYPE_HELLO:
        {
            int i;
            char port[6]; /* need this so port str can have null term. */
            char addrstr[ADDRSTRLEN];
            uint16_t req_id;
            
            if(id != 0)
                break;

            req_id = ntohs(*((uint16_t*)data));
            data += sizeof(uint16_t);
            data_len -= sizeof(uint16_t);
            
            /* look for the space separating the host and port */
            for(i = 0; i < data_len; i++)
                if(data[i] == ' ')
                    break;
            if(i == data_len)
                break;

            /* null terminate the host and get the port number to the string */
            data[i++] = 0;
            strncpy(port, data+i, data_len-i);
            port[data_len-i] = 0;

            if (!destination_allowed(allowed_destinations, data, port))
            {
                if (debug_level >= DEBUG_LEVEL1)
                    printf("Connection to %s:%s denied\n", data, port);
                msg_send_msg(from, next_client_id, MSG_TYPE_GOODBYE, NULL, 0);
                return -2;
            }
            
            /* Create an unconnected TCP socket for the remote host, the
               client itself, add it to the list of clients */
            tcp_sock = sock_create(data, port, ipver, SOCK_TYPE_TCP, 0, 0);
            ERROR_GOTO(tcp_sock == NULL, "Error creating tcp socket", error);

            c = client_create(next_client_id++, tcp_sock, from, 0);
            sock_free(tcp_sock);
            ERROR_GOTO(c == NULL, "Error creating client", error);

            c2 = list_add(clients, c);
            ERROR_GOTO(c2 == NULL, "Error adding client to list", error);

            if(debug_level >= DEBUG_LEVEL1)
            {
                sock_get_str(c2->udp_sock, addrstr, sizeof(addrstr));
                printf("New connection(%d): udp://%s", CLIENT_ID(c2), addrstr);
                sock_get_str(c2->tcp_sock, addrstr, sizeof(addrstr));
                printf(" -> tcp://%s\n", addrstr);
            }
            
            /* Send the Hello ACK message if created client successfully */
            client_send_helloack(c2, req_id);
            client_reset_keepalive(c2);
            client_free(c);
            
            break;
        }

        /* Can connect to TCP connection once received the Hello ACK */
        case MSG_TYPE_HELLOACK:
            client_got_helloack(c);
            client_connect_tcp(c, port_str);
            client_add_tcp_fd_to_set(c, client_fds);
            break;

        /* Resets the timeout of the client's keep alive time */
        case MSG_TYPE_KEEPALIVE:
            client_reset_keepalive(c);
            break;

        /* Receives the data it got from the UDP tunnel and sends it to the
           TCP connection. */
        case MSG_TYPE_DATA0:
        case MSG_TYPE_DATA1:
            ret = client_got_udp_data(c, data, data_len, msg_type);
            if(ret == 0)
                ret = client_send_tcp_data(c);
            break;

        /* Receives the ACK from the UDP tunnel to set the internal client
           state. */
        case MSG_TYPE_ACK0:
        case MSG_TYPE_ACK1:
            client_got_ack(c, msg_type);
            break;

        default:
            ret = -1;
    }

    return ret;

  error:
    return -1;
}

int destination_allowed(list_t *allowed_destinations,
                        const char *host, const char *port)
{
    int i;

    if (!allowed_destinations)
        return 1;

    for (i = 0; i < LIST_LEN(allowed_destinations); i++)
    {
        destination_t *dst = list_get_at(allowed_destinations, i);
        if ((!dst->host || !strcmp(dst->host, host))
             && (!dst->port || !strcmp(dst->port, port)))
            return 1;
    }

    return 0;
}

void signal_handler(int sig)
{
    switch(sig)
    {
        case SIGINT:
            running = 0;
    }
}

