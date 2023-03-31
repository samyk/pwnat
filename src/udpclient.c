/*
 * Project: udptunnel
 * File: udpclient.c
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
#include <time.h>
#include <sys/types.h>

#ifndef WIN32
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>

#include <inttypes.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#else
#include "gettimeofday.h"
#endif

#include "common.h"
#include "message.h"
#include "socket.h"
#include "packet.h"
#include "client.h"
#include "list.h"

extern int debug_level;
extern int ipver;
static int running = 1;
static uint16_t next_req_id;


/* internal functions */
static int handle_message(client_t *c, uint16_t id, uint8_t msg_type,
                          char *data, int data_len);
static void disconnect_and_remove_client(uint16_t id, list_t *clients,
                                         fd_set *fds);
static void signal_handler(int sig);

bool isnumber(const char* str) {
    if (!str) {
        return false;
    }

    char* end;
    strtol(str, &end, 10);
    return *end == '\0';
}

/*
 * argv: [local ip] <local port> <proxy host> [proxy port] <remote host> <remote port>
 */
int udpclient(int argc, char* argv[])
{
    char *lhost, *lport, *phost, *pport, *rhost, *rport;
    list_t *clients;
    list_t *conn_clients;
    client_t *client;
    client_t *client2;
    socket_t *tcp_serv = NULL;
    socket_t *tcp_sock = NULL;
    socket_t *udp_sock = NULL;
    char data[MSG_MAX_LEN];
    char addrstr[ADDRSTRLEN];
    char pport_s[6] = "2222";
    
    struct timeval curr_time;
    struct timeval check_time;
    struct timeval check_interval;
    struct timeval timeout;
    fd_set client_fds;
    fd_set read_fds;
    uint16_t tmp_id;
    uint8_t tmp_type;
    uint16_t tmp_len;
    uint16_t tmp_req_id;
    int num_fds;
    
    int ret;
    int i;

    int icmp_sock = 0;
    int timeexc = 0;

    struct sockaddr_in src, dest, rsrc;
    struct hostent *hp;
    uint32_t timeexc_ip;

    signal(SIGINT, &signal_handler);

    // Parse arguments
    i = 0;    
    if (!isnumber(argv[i]))
        lhost = argv[i++];
    else	
        lhost = NULL;
    lport = argv[i++];
    phost = argv[i++];
    if (isnumber(argv[i]))
        pport = argv[i++];
    else	
        pport = pport_s;
    rhost = argv[i++];
    rport = argv[i++];

    /* Get address from the machine */
	rsrc.sin_family = PF_INET;
	rsrc.sin_addr.s_addr = INADDR_ANY;
	if (lhost)
	{
		hp = gethostbyname(lhost);
		memcpy(&rsrc.sin_addr, hp->h_addr, hp->h_length); 
		inet_pton(AF_INET, lhost, &(rsrc.sin_addr));
	}

	/* IP of destination */
	memset(&src, 0, sizeof(struct sockaddr_in));
	hp					  = gethostbyname(phost);
	timeexc_ip            = *(uint32_t*)hp->h_addr_list[0];
	src.sin_family        = AF_INET;
	src.sin_port          = 0;
	src.sin_addr.s_addr   = timeexc_ip;

    /* IP of where the fake packet (echo request) was going */
	hp = gethostbyname("3.3.3.3");
	memcpy(&dest.sin_addr, hp->h_addr, hp->h_length); 
	inet_pton(AF_INET, "3.3.3.3", &(dest.sin_addr));
 
    srand(time(NULL));
    next_req_id = rand() % 0xffff;
    
    /* Create an empty list for the clients */
    clients = list_create(sizeof(client_t), p_client_cmp, p_client_copy,
                          p_client_free);
    ERROR_GOTO(clients == NULL, "Error creating clients list.", done);

    /* Create and empty list for the connecting clients */
    conn_clients = list_create(sizeof(client_t), p_client_cmp, p_client_copy,
                               p_client_free);
    ERROR_GOTO(conn_clients == NULL, "Error creating clients list.", done);

    /* Create a TCP server socket to listen for incoming connections */
    tcp_serv = sock_create(lhost, lport, ipver, SOCK_TYPE_TCP, 1, 1);
    ERROR_GOTO(tcp_serv == NULL, "Error creating TCP socket.", done);
    if(debug_level >= DEBUG_LEVEL1)
    {
        printf("Listening on TCP %s\n",
               sock_get_str(tcp_serv, addrstr, sizeof(addrstr)));
    }
    
    FD_ZERO(&client_fds);

    /* Initialize all the timers */
    timerclear(&timeout);
    check_interval.tv_sec = 0;
    check_interval.tv_usec = 500000;
    gettimeofday(&check_time, NULL);
    
    /* open raw socket */
	icmp_sock = create_icmp_socket();
    if (icmp_sock == -1) {
        printf("[main] can't open raw socket\n");
        exit(1);
    }

    while(running)
    {
        if(!timerisset(&timeout))
            timeout.tv_usec = 50000;

		if (timeexc++ % 100 == 0)
		{
			/* Send ICMP TTL exceeded to penetrate remote NAT */
			send_icmp(icmp_sock, &rsrc, &src, &dest, 0);
		}

        read_fds = client_fds;
        FD_SET(SOCK_FD(tcp_serv), &read_fds);

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

                ret = client_check_and_resend(client, curr_time);
                if(ret == -2)
                {
                    disconnect_and_remove_client(CLIENT_ID(client), clients,
                                                 &client_fds);
                    i--;
                    continue;
                }

                ret = client_check_and_send_keepalive(client, curr_time);
                if(ret == -2)
                {
                    disconnect_and_remove_client(CLIENT_ID(client), clients,
                                                 &client_fds);
                    i--;
                }
            }

            timeradd(&curr_time, &check_interval, &check_time);
        }
        
        if(num_fds == 0)
            continue;

        /* Check if pending TCP connection to accept and create a new client
           and UDP connection if one is ready */
        if(FD_ISSET(SOCK_FD(tcp_serv), &read_fds))
        {
            tcp_sock = sock_accept(tcp_serv);            
            udp_sock = sock_create(phost, pport, ipver,
                                   SOCK_TYPE_UDP, 0, 1);

            client = client_create(next_req_id++, tcp_sock, udp_sock, 1);
            if(!client || !tcp_sock || !udp_sock)
            {
                if(tcp_sock)
                    sock_close(tcp_sock);
                if(udp_sock)
                    sock_close(udp_sock);
            }
            else
            {
                client2 = list_add(conn_clients, client);
                client_free(client);
                client = NULL;
                
                client_send_hello(client2, rhost, rport, CLIENT_ID(client2));
                client_add_tcp_fd_to_set(client2, &client_fds);
                client_add_udp_fd_to_set(client2, &client_fds);
            }
            
            sock_free(tcp_sock);
            sock_free(udp_sock);
            tcp_sock = NULL;
            udp_sock = NULL;

            num_fds--;
        }

        /* Check for pending handshakes from UDP connection */
        for(i = 0; i < LIST_LEN(conn_clients) && num_fds > 0; i++)
        {
            client = list_get_at(conn_clients, i);
            
            if(client_udp_fd_isset(client, &read_fds))
            {
                num_fds--;
                tmp_req_id = CLIENT_ID(client);

                ret = client_recv_udp_msg(client, data, sizeof(data),
                                          &tmp_id, &tmp_type, &tmp_len);
                if(ret == 0)
                    ret = handle_message(client, tmp_id, tmp_type,
                                         data, tmp_len);
                if(ret < 0)
                {
                    disconnect_and_remove_client(tmp_req_id, conn_clients,
                                                 &client_fds);
                    i--;
                }
                else
                {
                    client = list_add(clients, client);
                    list_delete_at(conn_clients, i);
                    client_remove_udp_fd_from_set(client, &read_fds);
                    i--;
                }
            }
        }

        /* Check if data is ready from any of the clients */
        for(i = 0; i < LIST_LEN(clients) && num_fds > 0; i++)
        {
            client = list_get_at(clients, i);

            /* Check for UDP data */
            if(client_udp_fd_isset(client, &read_fds))
            {
                num_fds--;

                ret = client_recv_udp_msg(client, data, sizeof(data),
                                          &tmp_id, &tmp_type, &tmp_len);
                if(ret == 0)
                    ret = handle_message(client, tmp_id, tmp_type,
                                         data, tmp_len);
                if(ret < 0)
                {
                    disconnect_and_remove_client(CLIENT_ID(client), clients,
                                                 &client_fds);
                    i--;
                    continue; /* Don't go to check the TCP connection */
                }
            }

            /* Check for TCP data */
            if(client_tcp_fd_isset(client, &read_fds))
            {
                num_fds--;

                ret = client_recv_tcp_data(client);
                if(ret == 0)
                    ret = client_send_udp_data(client);
#if 0 /* if udptunnel is taking up 100% of cpu, try including this */
                else if(ret == 1)
#ifdef WIN32
                    _sleep(1);
#else
                    usleep(1000); /* Quick hack so doesn't use 100% of CPU if
                                     data wasn't ready yet (waiting for ack) */
#endif /*WIN32*/
#endif /*0*/          
                
                if(ret < 0)
                {
                    disconnect_and_remove_client(CLIENT_ID(client), clients,
                                                 &client_fds);
                    i--;
                }
            }
        }
    }
    
  done:
    if(debug_level >= DEBUG_LEVEL1)
        printf("Cleaning up...\n");
    if(tcp_serv)
    {
        sock_close(tcp_serv);
        sock_free(tcp_serv);
    }
    if(udp_sock)
    {
        sock_close(udp_sock);
        sock_free(udp_sock);
    }
    if(clients)
        list_free(clients);
    if(debug_level >= DEBUG_LEVEL1)
        printf("Goodbye.\n");
    return 0;
}

/*
 * Closes the TCP and UDP connections for the client and remove its stuff from
 * the lists.
 */
void disconnect_and_remove_client(uint16_t id, list_t *clients, fd_set *fds)
{
    client_t *c;

    c = list_get(clients, &id);
    if(!c)
        return;

    client_send_goodbye(c);

    if(debug_level >= DEBUG_LEVEL1)
        printf("Client %d disconnected.\n", CLIENT_ID(c));
    
    client_remove_udp_fd_from_set(c, fds);
    client_remove_tcp_fd_from_set(c, fds);
    client_disconnect_tcp(c);
    client_disconnect_udp(c);
    list_delete(clients, &id);
}

/*
 * Handles a message received from the UDP tunnel. Returns 0 if successful, -1
 * on some error it handled, or -2 if the client is to disconnect.
 */
int handle_message(client_t *c, uint16_t id, uint8_t msg_type,
                   char *data, int data_len)
{
    int ret = 0;
    char addrstr[ADDRSTRLEN];
    
    switch(msg_type)
    {
        case MSG_TYPE_GOODBYE:
            ret = -2;
            break;
            
        case MSG_TYPE_HELLOACK:
            client_got_helloack(c);
            CLIENT_ID(c) = id;
            ret = client_send_helloack(c, ntohs(*((uint16_t *)data)));

            if(debug_level >= DEBUG_LEVEL1)
            {
                sock_get_str(c->tcp_sock, addrstr, sizeof(addrstr));
                printf("New connection(%d): tcp://%s", CLIENT_ID(c), addrstr);
                sock_get_str(c->udp_sock, addrstr, sizeof(addrstr));
                printf(" -> udp://%s\n", addrstr);
            }
            break;
            
        case MSG_TYPE_DATA0:
        case MSG_TYPE_DATA1:
            ret = client_got_udp_data(c, data, data_len, msg_type);
            if(ret == 0)
                ret = client_send_tcp_data(c);
            break;
            
        case MSG_TYPE_ACK0:
        case MSG_TYPE_ACK1:
            ret = client_got_ack(c, msg_type);
            break;
            
        default:
            ret = -1;
            break;
    }

    return ret;
}

void signal_handler(int sig)
{
    switch(sig)
    {
        case SIGINT:
            running = 0;
    }
}
