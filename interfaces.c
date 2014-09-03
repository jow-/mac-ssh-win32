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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include "utils.h"
#include "protocol.h"
#include "interfaces.h"

LIST_HEAD(ifaces);

static fd_set selectset;
static unsigned char packetbuf[1500];


int net_recv_packet(int fd, struct mt_mactelnet_hdr *h, struct sockaddr_in *s)
{
	int result;
	struct sockaddr_in dummy;
	int slen = sizeof(dummy);

	memset(packetbuf, 0, sizeof(packetbuf));

	result = recvfrom(fd, (char *)packetbuf, sizeof(packetbuf), 0,
	                  (struct sockaddr *)(s ? s : &dummy), &slen);

	if (result > 0 && h)
		parse_packet(packetbuf, h);

	return result;
}

void net_enum_ifaces(void)
{
	int rv, i = 0;
	unsigned long len = 15000;
	PIP_ADAPTER_INFO ifa, ifas;
	struct net_interface *iface, *tmp;

	if (!list_empty(&ifaces))
	{
		list_for_each_entry_safe(iface, tmp, &ifaces, list)
		{
			list_del(&iface->list);
			free(iface);
		}
	}

    do {
        ifas = (IP_ADAPTER_INFO *) malloc(len);

		if (!ifas)
			return;

        rv = GetAdaptersInfo(ifas, &len);

		if (rv == ERROR_SUCCESS)
			break;

        free(ifas);
        ifas = NULL;
    }
	while ((rv == ERROR_BUFFER_OVERFLOW) && (++i < 5));

	if (!ifas)
		return;

	iface = calloc(1, sizeof(*iface));

	if (!iface)
		return;

	for (ifa = ifas; ifa; ifa = ifa->Next)
	{
		if (ifa->AddressLength != sizeof(iface->mac_addr))
			continue;

		memcpy(iface->mac_addr, ifa->Address, sizeof(iface->mac_addr));
		strncpy(iface->name, ifa->AdapterName, sizeof(iface->name) - 1);

		iface->ipv4_addr.s_addr =
			inet_addr(ifa->IpAddressList.IpAddress.String);

		iface->ipv4_bcast.s_addr =
			iface->ipv4_addr.s_addr |
				~inet_addr(ifa->IpAddressList.IpMask.String);
	}

	list_add_tail(&iface->list, &ifaces);
}

int _net_select(int timeout, ...)
{
	va_list ap;
	SOCKET sock;
	struct timeval t;

	FD_ZERO(&selectset);

	va_start(ap, timeout);

	while (1)
	{
		sock = va_arg(ap, SOCKET);

		if (sock == INVALID_SOCKET)
			break;

		FD_SET(sock, &selectset);
	}

	va_end(ap);

	t.tv_sec = timeout / 1000;
	t.tv_usec = (timeout % 1000) * 1000;

	return select(-1, &selectset, NULL, NULL, &t);
}

int net_readable(SOCKET sock, int timeout)
{
	if (timeout > 0)
		net_select(timeout, sock);

	return FD_ISSET(sock, &selectset);
}
