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

#ifndef _INTERFACES_H
#define _INTERFACES_H 1

#include <stdint.h>
#include <stdarg.h>
#include <winsock2.h>

#include "utils.h"

#define ETH_ALEN 6


static inline char * macstr(unsigned char *mac)
{
	static char buf[sizeof("FF:FF:FF:FF:FF:FF\0")];

	snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
	         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return buf;
}


struct net_interface {
	char name[255];
	struct in_addr ipv4_addr;
	struct in_addr ipv4_bcast;
	unsigned char mac_addr[ETH_ALEN];

	struct list_head list;
};


extern struct list_head ifaces;

void net_enum_ifaces(void);

int net_recv_packet(int fd, struct mt_mactelnet_hdr *h, struct sockaddr_in *s);

#define net_select(timeout, ...) \
	_net_select(timeout, ##__VA_ARGS__, INVALID_SOCKET)

int _net_select(int timeout, ...);
int net_readable(SOCKET sock, int timeout);

#endif
