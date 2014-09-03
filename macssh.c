/*
	MacSSH - MAC-Telnet SSH Connect utility for Windows
	Copyright (C) 2014, Jo-Philipp Wich <jow@openwrt.org>

	Based on MAC-Telnet with SSH extension support.
	Copyright (C) 2011, Ali Onur Uyar <aouyar@gmail.com>

	Based on MAC-Telnet implementation for Linux.
	Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>


	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along
	with this program; if not, write to the Free Software Foundation, Inc.,
	51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <libgen.h>

#include "pgetopt.h"
#include "protocol.h"
#include "interfaces.h"
#include "utils.h"
#include "macssh.h"
#include "mndp.h"


#define PROGRAM_NAME "MAC-SSH"

SOCKET macrecv, macsend, sshserv, sshclient;

static unsigned int outcounter = 0;
static unsigned int incounter = 0;
static int sessionkey = 0;
static int running = 1;

static int sourceport;
static int sshport = MT_TUNNEL_CLIENT_PORT;

static int connect_timeout = CONNECT_TIMEOUT;
static int mndp_timeout = 0;

static int keepalive_counter = 0;

static char *username = "root";
static char *password = NULL;

struct net_interface *outiface;
struct mndphost *server = NULL;

struct args {
	int c;
	char **v;
};

extern int plink_main(int argc, char **argv);


static int handle_packet(struct mt_mactelnet_hdr *pkt, int data_len);

static void print_version() {
	fprintf(stderr, PROGRAM_NAME " " PROGRAM_VERSION "\n");
}

static int send_udp(struct mt_packet *packet, int retransmit) {
	int sent_bytes;
	struct mt_mactelnet_hdr hdr = { };

	/* Clear keepalive counter */
	keepalive_counter = 0;

	/* Init SendTo struct */
	struct sockaddr_in socket_address;
	memset(&socket_address, 0, sizeof(socket_address));
	socket_address.sin_family = AF_INET;
	socket_address.sin_port = htons(MT_MACTELNET_PORT);
	socket_address.sin_addr = outiface->ipv4_bcast;


	sent_bytes = sendto(macsend, (char *)packet->data, packet->size, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));

	/*
	 * Retransmit packet if no data is received within
	 * retransmit_intervals milliseconds.
	 */
	if (retransmit)
	{
		int i;

		for (i = 0; i < MAX_RETRANSMIT_INTERVALS; ++i)
		{
			/* Wait for data or timeout */
			if (net_readable(macrecv, retransmit_intervals[i]))
			{
				int result = net_recv_packet(macrecv, &hdr, NULL);

				/* Handle incoming packets, waiting for an ack */
				if (result > 0 && handle_packet(&hdr, result) == MT_PTYPE_ACK)
					return sent_bytes;
			}

			/* Retransmit */
			send_udp(packet, 0);
		}

		fprintf(stderr, "\nConnection timed out\n");
		exit(1);
	}

	return sent_bytes;
}

static int disconnect(int seskey)
{
	struct mt_packet data;

	if (!outiface)
		return -1;

	/* Acknowledge the disconnection by sending a END packet in return */
	init_packet(&data, MT_PTYPE_END, outiface->mac_addr, server->address, seskey, 0);
	send_udp(&data, 0);

	fprintf(stderr, "MAC connection closed.\n");

	/* exit */
	running = 0;

	return MT_PTYPE_END;
}

static void finish(void)
{
	if (sessionkey != 0)
		disconnect(sessionkey);
}

static int handle_data(struct mt_mactelnet_hdr *pkt, int data_len)
{
	struct mt_packet odata;
	struct mt_mactelnet_control_hdr cpkt;
	int success = 0;

	/* Always transmit ACKNOWLEDGE packets in response to DATA packets */
	init_packet(&odata, MT_PTYPE_ACK, outiface->mac_addr, server->address,
	            sessionkey, pkt->counter + (data_len - MT_HEADER_LEN));

	send_udp(&odata, 0);

	/* Accept first packet, and all packets greater than incounter, and if counter has
	wrapped around. */
	if (incounter == 0 || pkt->counter > incounter || (incounter - pkt->counter) > 65535)
		incounter = pkt->counter;
	else
		/* Ignore double or old packets */
		return -1;

	/* Parse controlpacket data */
	success = parse_control_packet(pkt->data, data_len - MT_HEADER_LEN, &cpkt);

	while (success)
	{
		/* Using MAC-SSH server must not send authentication request.
		 * Authentication is handled by tunneled SSH Client and Server.
		 */
		if (cpkt.cptype == MT_CPTYPE_ENCRYPTIONKEY)
		{
			fprintf(stderr, "Server %s does not seem to use MAC-SSH Protocol. Please Try using MAC-Telnet instead.\n", macstr(server->address));
			exit(1);
		}

		/* If the (remaining) data did not have a control-packet magic byte sequence,
		   the data is raw terminal data to be tunneled to local SSH Client. */
		else if (cpkt.cptype == MT_CPTYPE_PLAINDATA)
		{
			if (send(sshclient, (char *)cpkt.data, cpkt.length, 0) < 0)
			{
				fprintf(stderr, "Terminal client disconnected.\n");
				/* exit */
				running = 0;
			}
		}

		/* Parse next controlpacket */
		success = parse_control_packet(NULL, 0, &cpkt);
	}

	return pkt->ptype;
}

static int handle_packet(struct mt_mactelnet_hdr *pkt, int data_len)
{
	/* We only care about packets with correct sessionkey */
	if (pkt->seskey != sessionkey)
		return -1;

	/* Handle data packets */
	switch (pkt->ptype)
	{
	case MT_PTYPE_DATA:
		return handle_data(pkt, data_len);

	case MT_PTYPE_ACK:
		return MT_PTYPE_ACK;

	case MT_PTYPE_END:
		return disconnect(pkt->seskey);

	default:
		fprintf(stderr, "Unhandeled packet type: %d received from server %s\n",
		        pkt->ptype, macstr(server->address));
		return -1;
	}
}

static int find_interface()
{
	struct mt_packet data;
	struct sockaddr_in local;
	int opt = 1;
	struct net_interface *iface;
	SOCKET mactest;

	list_for_each_entry(iface, &ifaces, list)
	{
		/* Initialize receiving socket on the device chosen */
		local.sin_family = AF_INET;
		local.sin_port = htons(sourceport);
		local.sin_addr = iface->ipv4_addr;

		/* Initialize socket and bind to udp port */
		mactest = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

		if (mactest == SOCKET_ERROR)
			continue;

		setsockopt(mactest, SOL_SOCKET, SO_BROADCAST, (char *)&opt, sizeof(opt));
		setsockopt(mactest, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));

		if (bind(mactest, (struct sockaddr *)&local, sizeof(local)) == SOCKET_ERROR)
		{
			closesocket(mactest);
			continue;
		}

		/* Set the global socket handle and source mac address for send_udp() */
		macsend = mactest;
		outiface = iface;

		/* Send a SESSIONSTART message with the current device */
		init_packet(&data, MT_PTYPE_SESSIONSTART, outiface->mac_addr, server->address, sessionkey, 0);
		send_udp(&data, 0);

		/* We got a response, this is the correct device to use */
		if (net_readable(macrecv, connect_timeout * 1000))
			return 1;

		closesocket(mactest);
	}
	return 0;
}

DWORD WINAPI launch_plink(LPVOID lpParam)
{
	struct args *ssh_arg = (struct args *)lpParam;

	atexit(finish);

	return plink_main(ssh_arg->c, ssh_arg->v);
}

static void select_mndp(void)
{
	int rv, n;
	char line[128];
	struct mndphost *host;

	printf("Performing MNDP discovery...\n");

	rv = mndp_discover(3);

	if (rv > 0)
	{
		n = 1;

		list_for_each_entry(host, &mndphosts, list)
		{
			printf(" %2d) %s %s", n++, macstr(host->address), host->identity);

			if (host->platform)
				printf(" (%s %s %s)",
				       host->platform, host->version, host->hardware);

			if (host->uptime)
				printf("  up %d days %d hours",
				       host->uptime / 86400, host->uptime % 86400 / 3600);

			printf("\n");
		}

		printf("\n");

		n = 1;

		if (rv > 1)
		{
			do {
				printf("\nEnter host number [1-%d] > ", rv);

				fgets(line, sizeof(line - 1), stdin);
				n = atoi(line);

				if (n > 0 && n <= rv)
					break;
			}
			while (1);
		}

		list_for_each_entry(host, &mndphosts, list)
			if (n-- <= 1)
			{
				server = host;
				return;
			}
	}

	printf("No hosts found\n");
}

static int setup_ssh_socket(int port)
{
	int opt = 1;
	int sshsock;
	struct sockaddr_in local;

	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	local.sin_addr.s_addr = inet_addr("127.0.0.1");

	sshsock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (sshsock == SOCKET_ERROR)
	{
		fprintf(stderr, "SSH socket create: %d\n", WSAGetLastError());
		goto err;
	}

	setsockopt(sshsock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));

	if (bind(sshsock, (struct sockaddr *)&local, sizeof(local)) == SOCKET_ERROR)
	{
		fprintf(stderr, "SSH socket bind: %d\n", WSAGetLastError());
		goto err;
	}

	if (listen(sshsock, 1) == SOCKET_ERROR)
	{
		fprintf(stderr, "SSH socket listen: %d\n", WSAGetLastError());
		goto err;
	}

	return sshsock;

err:
	if (sshsock != SOCKET_ERROR)
		closesocket(sshsock);

	return SOCKET_ERROR;
}

static int setup_mac_socket(int port)
{
	int opt = 1;
	int macrecv;
	struct sockaddr_in local;

	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	local.sin_addr.s_addr = htonl(INADDR_ANY);

	macrecv = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (macrecv == SOCKET_ERROR)
	{
		fprintf(stderr, "MAC socket create: %d\n", WSAGetLastError());
		goto err;
	}

	setsockopt(macrecv, SOL_SOCKET, SO_BROADCAST, (char *)&opt, sizeof(opt));
	setsockopt(macrecv, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));

	if (bind(macrecv, (struct sockaddr *)&local, sizeof(local)) == SOCKET_ERROR)
	{
		fprintf(stderr, "MAC socket bind: %d\n", WSAGetLastError());
		goto err;
	}

	return macrecv;

err:
	if (macrecv != SOCKET_ERROR)
		closesocket(macrecv);

	return SOCKET_ERROR;
}

static int accept_ssh_client(int sshsock)
{
	struct sockaddr_in remote;
	int sl = sizeof(remote);
	int clientsock;
	int opt = 1;

	fprintf(stderr, "Connecting: ");

	clientsock = accept(sshsock, (struct sockaddr *)&remote, &sl);

	if (clientsock == SOCKET_ERROR)
	{
		fprintf(stderr, "accept failed: %d\n", WSAGetLastError());
		goto err;
	}

	setsockopt(clientsock, SOL_SOCKET, SO_KEEPALIVE, (char *)&opt, sizeof(opt));

	fprintf(stderr, "TCP (%d\x1D%d) \x1A ", ntohs(remote.sin_port), sshport);

	return clientsock;

err:
	if (clientsock != SOCKET_ERROR)
		closesocket(clientsock);

	return SOCKET_ERROR;
}

BOOL WINAPI handle_console_event(DWORD signal)
{
	DWORD written;
	INPUT_RECORD ir[2] = { };
	HANDLE console = GetStdHandle(STD_INPUT_HANDLE);

    if (signal == CTRL_C_EVENT)
	{
		ir[0].EventType = KEY_EVENT;
		ir[0].Event.KeyEvent.bKeyDown = TRUE;
		ir[0].Event.KeyEvent.wRepeatCount = 1;
		ir[0].Event.KeyEvent.wVirtualKeyCode = 3; /* Ctrl-C */
		ir[0].Event.KeyEvent.uChar.AsciiChar = 3; /* Ctrl-C */

		WriteConsoleInput(console, ir, 1, &written);
	}
	else
	{
		ir[0].EventType = KEY_EVENT;
		ir[0].Event.KeyEvent.bKeyDown = TRUE;
		ir[0].Event.KeyEvent.wRepeatCount = 1;
		ir[0].Event.KeyEvent.wVirtualKeyCode = 3; /* Ctrl-C */
		ir[0].Event.KeyEvent.uChar.AsciiChar = 3; /* Ctrl-C */

		ir[1].EventType = KEY_EVENT;
		ir[1].Event.KeyEvent.bKeyDown = TRUE;
		ir[1].Event.KeyEvent.wRepeatCount = 1;
		ir[1].Event.KeyEvent.wVirtualKeyCode = 4; /* Ctrl-D */
		ir[1].Event.KeyEvent.uChar.AsciiChar = 4; /* Ctrl-D */

		WriteConsoleInput(console, ir, 2, &written);

		if (sessionkey)
			disconnect(sessionkey);
	}

    return TRUE;
}

/*
 * TODO: Rewrite main() when all sub-functionality is tested
 */
int main (int argc, char **argv) {
	int result;
	struct mt_packet data;
	struct mt_mactelnet_hdr hdr = { };
	unsigned char print_help = 0;
	int c;

	WSADATA wsd;
	WSAStartup(MAKEWORD(2,2), &wsd);

    /* Ignore args after -- for MAC-Telnet client. */
	int macssh_argc = argc;
	int i;
	for (i=0; i < argc; i++) {
		if (strlen(argv[i]) == 2 && strncmp(argv[i], "--", 2) == 0) {
			macssh_argc = i;
			break;
		}
	}

	while ((c = pgetopt(macssh_argc, argv, "qt:u:p:vh?P:")) != -1)
	{
		switch (c)
		{
			case 'P':
				sshport = atoi(poptarg);
				break;

			case 'u':
				username = poptarg;
				break;

			case 'p':
				password = poptarg;
				break;

			case 't':
				connect_timeout = atoi(poptarg);
				mndp_timeout = connect_timeout;
				break;

			case 'v':
				print_version();
				exit(0);
				break;

			case 'h':
			case '?':
				print_help = 1;
				break;

		}
	}

	if (print_help)
	{
		print_version();
		fprintf(stderr, "Usage: %s <MAC|identity> [-v] [-h] [-q] [-n] [-l] [-B] [-S] [-P <port>] "
		                "[-t <timeout>] [-u <user>] [-p <pass>] [-c <path>] [-U <user>]\n", argv[0]);

		if (print_help) {
			fprintf(stderr, "\nParameters:\n"
			"  MAC            MAC-Address of the RouterOS/mactelnetd device. Use MNDP to \n"
			"                 discover it.\n"
			"  identity       The identity/name of your destination device. Uses MNDP \n"
			"                 protocol to find it.\n"
			"  -l             List/Search for routers nearby (MNDP). You may use -t to set timeout.\n"
			"  -B             Batch mode. Use computer readable output (CSV), for use with -l.\n"
			"  -n             Do not use broadcast packets. Less insecure but requires\n"
			"                 root privileges.\n"
			"  -t <timeout>   Amount of seconds to wait for a response on each interface.\n"
			"  -u <user>      Specify username on command line.\n"
			"  -p <password>  Specify password on command line.\n"
			"  -U <user>      Drop privileges to this user. Used in conjunction with -n\n"
			"                 for security.\n"
			"  -P <port>      Local TCP port for forwarding SSH connection.\n"
			"                 (If not specified, port 2222 by default.)\n"
			"  -q             Quiet mode.\n"
			"  -v             Print version and exit.\n"
			"  -h             This help.\n"
			"\n"
			"All arguments after '--' will be passed to the ssh client command.\n"
			"\n");
		}
		return 1;
	}

	net_enum_ifaces();
	select_mndp();

	if (!server)
		return 1;

	SetConsoleCtrlHandler(handle_console_event, TRUE);

	struct args ssh_arg;

	/* Setup command line for ssh client */
	int add_argc;

	add_argc = argc - macssh_argc;
	ssh_arg.c = add_argc;
	ssh_arg.c += 3; /* Port option and hostname: -p <port> <host>  */

	if (username)
		ssh_arg.c += 2; /* Username: -l <user> */

	if (password)
		ssh_arg.c += 2; /* Password: -pw <password> */

	ssh_arg.v = (char **) calloc(sizeof(char *), ssh_arg.c + 1);
	ssh_arg.c = 0;

	ssh_arg.v[ssh_arg.c++] = "plink.exe";

	for (i = 1; i < add_argc; i++)
		ssh_arg.v[ssh_arg.c++] = argv[macssh_argc + i];

	char portstr[8];
	snprintf(portstr, 8, "%d", sshport);
	ssh_arg.v[ssh_arg.c++] = "-P";
	ssh_arg.v[ssh_arg.c++] = strdup(portstr); //, sizeof(portstr) - 1);

	if (username)
	{
		ssh_arg.v[ssh_arg.c++] = "-l";
		ssh_arg.v[ssh_arg.c++] = username;
	}

	if (password)
	{
		ssh_arg.v[ssh_arg.c++] = "-pw";
		ssh_arg.v[ssh_arg.c++] = password;
	}

	ssh_arg.v[ssh_arg.c++] = "127.0.0.1";
	ssh_arg.v[ssh_arg.c] = (char *)NULL;

	/* Seed randomizer */
	//srand(time(NULL));

	/* Set random source port */
	sourceport = 1024 + (rand() % 1024);

	/* Session key */
	sessionkey = rand() % 65535;

	if ((macrecv = setup_mac_socket(sourceport)) == SOCKET_ERROR)
		return 1;

	/* Setup Server socket for receiving connection from local SSH Client. */
	if ((sshserv = setup_ssh_socket(sshport)) == SOCKET_ERROR)
		return 1;

	/* Fork child to execute SSH Client locally and connect to parent
	 * waiting for connection from child if launch_ssh is requested.
	 */

	CreateThread(NULL, 0, launch_plink, &ssh_arg, 0, NULL);

	/* Wait for remote terminal client connection on server port. */
	if ((sshclient = accept_ssh_client(sshserv)) == SOCKET_ERROR)
		return 1;

	/* stop output buffering */
	setvbuf(stdout, (char*)NULL, _IONBF, 0);

	if (!find_interface() || (result = net_recv_packet(macrecv, &hdr, NULL)) < 1) {
		fprintf(stderr, "MAC connection failed.\n");
		return 1;
	}

	fprintf(stderr, "MAC (%s", macstr(outiface->mac_addr));
	fprintf(stderr, "\x1D%s) \x1A ", macstr(server->address));

	/* Handle first received packet */
	if (handle_packet(&hdr, result) >= 0)
		fprintf(stderr, "SSH\n");

	init_packet(&data, MT_PTYPE_DATA, outiface->mac_addr, server->address, sessionkey, 0);
	outcounter +=  add_control_packet(&data, MT_CPTYPE_BEGINAUTH, NULL, 0);

	/* TODO: handle result of send_udp */
	result = send_udp(&data, 1);

	while (running)
	{
		/* Wait for data or timeout */
		if (net_select(1000, macrecv, sshclient) > 0)
		{
			/* Handle data from server */
			if (net_readable(macrecv, -1))
			{
				result = net_recv_packet(macrecv, &hdr, NULL);

				if (result > 0)
					handle_packet(&hdr, result);
			}

			unsigned char keydata[512];
			int datalen = 0;
			/* Handle data from local SSH client */
			if (net_readable(sshclient, -1)) {
				datalen = recv(sshclient, (char *)keydata, 512, 0);
				if (datalen <= 0)
					disconnect(sessionkey);
			}

			if (datalen > 0) {
				/* Data received, transmit to server */
				init_packet(&data, MT_PTYPE_DATA, outiface->mac_addr, server->address, sessionkey, outcounter);
				add_control_packet(&data, MT_CPTYPE_PLAINDATA, &keydata, datalen);
				outcounter += datalen;
				send_udp(&data, 1);
			}
		}

		/* Handle select() timeout */
		else
		{
			/* handle keepalive counter, transmit keepalive packet every 10 seconds
			   of inactivity  */
			if (keepalive_counter++ == 10) {
				struct mt_packet odata;
				init_packet(&odata, MT_PTYPE_ACK, outiface->mac_addr, server->address, sessionkey, outcounter);
				send_udp(&odata, 0);
			}
		}
	}

	closesocket(macrecv);

	if (sshclient > 0)
		closesocket(sshclient);

	return 0;
}
