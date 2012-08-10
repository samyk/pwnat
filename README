pwnat - http://samy.pl/pwnat

pwnat, by Samy Kamkar, is a tool that allows any client
behind a NAT to communicate with a server behind a
separate NAT with *no* port forwarding and *no* DMZ
setup on any routers in order to directly communicate
with each other.

There is no middle man, no proxy, no 3rd party, no UPnP
required, no spoofing, no DNS tricks. The server does
not need to know the client's IP address before connecting.

More importantly, the client can then connect to any
host or port on any remote host or to a fixed host and
port decided by the server.

Simply put, this is a proxy server that works behind a NAT,
even when the client is also behind a NAT.

You can read the paper published in IEEE and presented at
the IEEE P2P'10 Conference here: http://samy.pl/pwnat/pwnat.pdf

usage: ./pwnat <-s | -c> <args>

  -c    client mode
        <args>: [local ip] <local port> <proxy host> [proxy port (def:2222)] <remote host> <remote port>

  -s    server mode
        <args>: [local ip] [proxy port (def:2222)] [[allowed host]:[allowed port] ...]

  -6    use IPv6
  -v    show debug output (up to 2)
  -h    show this help and exit


EXAMPLE:

Server side allowing anyone to proxy:
  ./pwnat -s

Client wanting to connect to google.com:80:
  ./pwnat -c 8000 <pwnat.server.com> google.com 80

Then, browse to http://localhost:8000 to visit the google!


FAQ
 Ok, so does this really work?
	Yes. Try it!

    I'm confused. This can't work.
	You should be, and it does work.

    But it can't. My NAT blocks incoming packets and so will the other.
	I know.

    But how?!
	Great question! I thought you'd never ask.
	Look below at HOW DOES IT WORK?

    Does this use DNS for anything?
	No.

    Do I need to setup port forwarding or a DMZ on either end?
	No.

    Is there some sort of proxy or 3rd party that tunnels information between
    the two NATs?
	No. The connection is direct, client to server.

    Will this work behind my corporate NAT and firewall?
	This will work behind many NATs and firewalls, but not all.

    What uses does this have?
	This will allow you to tunnel any service that you want to run (http,
	ssh, quake server, IRC, ftp, etc.) through your NAT, or proxy into
	other remote servers.

    What if one or both ends aren't behind a NAT?
	Everything will work just as well. You can use pwnat to tunnel TCP
	payload over UDP if you wish; no NATs are necessary.

    Does the server have to specify the client host?
	No! The server doesn't know the client IP address until the client
	attempts to connect, penetrating the NAT using this unique method.

HOW DOES IT WORK?

    My method of penetrating NATs is two-fold which I will describe below.

    In order for the full tunnel to be established, the client side needs to
    know the public IP address of the server, and the server needs to learn
    the public IP address of the client.

    However, in a true client-server model, the server doesn't know the client IP
    until the client connects, and NATs will normally drop unknown incoming packets.
    In pwnat, the server also does not need to know the client IP address.

    Here is how the pwnat server learns the IP address of the client:
    I get around this by having the client "pretend" to be a random hop on
    the Internet. I'm essentially using the same technology a traceroute uses
    to detect hops on the Internet, but I'm doing the reverse in order to
    penetrate the NAT.

    Specifically, when the server starts up, it begins sending fixed ICMP echo
    request packets to the fixed address 3.3.3.3. We expect that these packets
    won't be returned.

    Now, 3.3.3.3 is *not* a host we have any access to, nor will we end up spoofing
    it. Instead, when a client wants to connect, the client (which knows the server
    IP address) sends an ICMP Time Exceeded packet to the server. The ICMP packet
    includes the "original" fixed packet that the server was sending to 3.3.3.3.

    Why? Well, we're pretending to be a hop on the Internet, politely telling the
    server that its original "ICMP echo request" packet couldn't be delivered.
    Your NAT, being the gapingly open device it is, is nice enough to notice that
    the packet *inside* the ICMP time exceeded packet matches the packet the server
    sent out. It then forwards the ICMP time exceeded back to the server behind
    the NAT, *including* the full IP header from the client, thus allowing the
    server to know what the client IP address is!

    Server (1.2.3.4): ICMP Echo Request -> 3.3.3.3
    ...
    Server (1.2.3.4): ICMP Echo Request -> 3.3.3.3
    ...
    Server (1.2.3.4): ICMP Echo Request -> 3.3.3.3
    ...
    Client (6.7.8.9): ICMP Time Exceeded (includes ICMP Echo Request to 3.3.3.3) -> 1.2.3.4
    Server's NAT: Sees server's Echo Request in client's Time Exceeded packet,
              sends entire packet to server because it matches server's outgoing packet

    Don't believe me? Just traceroute any host behind your NAT. You'll notice
    incoming packets coming in from random IP addresses your router knows
    nothing about. Your router knows to send those back to you, rather than another
    client on your network, based off of the data inside the ICMP time exceeded packet.

    Now, the server has only learned the client IP address. We still have no
    method to send any additional data. For the full communication, we use the
    same method used in my previous software, chownat, to penetrate both NATs.

    Example of a client behind a NAT talking to a machine NOT behind a NAT:
    Machine A -> NAT A -> net -> quake server

    Machine A sends a UDP packet to quake server, opening a "session".
    NAT A sees this and says:
    "If any UDP packets come back soon with the same host and port info,
    I'm routing it to machine A."
    Quake server sends UDP packets back, hits NAT A, and NAT A seeing the right
    hosts and ports, sends it to machine A. Machine A and quake server are now
    able to communicate without any problem.

    Now here is how pwnat works now that client and server know each others IP.
    Goal is: Machine A (ssh client) -> NAT A -> net -> NAT B -> Machine B (ssh server)

    When you start up the pwnat server on machine B, it slowly fires off
    UDP packets to machine A. Of course, NAT A is not expecting these so it
    drops every one of them. Machine B does not stop.

    Once you begin the pwnat client on machine A, it begins sending UDP
    packets to machine B. Note: pwnat defaults source and destination
    ports to 2222. Any unprivileged user can set UDP source and dest ports.
    Normally the UDP packets that machine A is sending to NAT B would get dropped.
    However, since machine B is sending similar packets OUT, NAT B assumes
    these are responses and lets them back in. Once machine B sees these packets,
    it sends handshake packets back to machine A. These packets will not get
    dropped by NAT A because of the same reason: NAT A sees packets going out, and
    the packets coming back to the NAT look like responses to the ones going out.

    Finally, both sides are fully communicating over UDP, allowing protocols that
    run over TCP to tunnel through.
    Note: There is a keep-alive process on the pwnat server and client that
    always keeps the UDP "session" active. The packets it sends have a 0 byte
    payload and are only sent when the client is not sending data out. Otherwise,
    the fastest it will possibly send the keep-alive packets is one packet every 5
    seconds. If any other type of data is traveling through the tunnel, no
    keep-alive packets will be transmitted.



by Samy Kamkar

pwnat is based off of udptunnel by Daniel Meekins:
http://code.google.com/p/udptunnel/

