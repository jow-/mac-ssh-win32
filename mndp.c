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

#include "utils.h"
#include "protocol.h"
#include "interfaces.h"
#include "mndp.h"

LIST_HEAD(mndphosts);

int mndp_discover(int timeout)
{
	int rv, sock, opt = 1, found = 0;
	struct net_interface *iface;
	struct mndphost *mndphost;
	struct mt_mndp_info *mndppkt;
	struct sockaddr_in local, remote;
	unsigned char buf[MT_PACKET_LEN];
	char *address, *identity, *platform, *version, *hardware;

	local.sin_family = AF_INET;
	local.sin_port = htons(MT_MNDP_PORT);
	local.sin_addr.s_addr = htonl(INADDR_ANY);

	remote.sin_family = AF_INET;
	remote.sin_port = htons(MT_MNDP_PORT);

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (sock == SOCKET_ERROR)
		goto err;

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
	setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char *)&opt, sizeof(opt));

	if (bind(sock, (struct sockaddr *)&local, sizeof(local)) == SOCKET_ERROR)
		goto err;

	list_for_each_entry(iface, &ifaces, list)
	{
		remote.sin_addr = iface->ipv4_bcast;

		sendto(sock, (char *)"\0\0\0\0", 4, 0,
		       (struct sockaddr *)&remote, sizeof(remote));
	}

	while (1)
	{
		rv = net_readable(sock, timeout * 1000);

		if (rv == SOCKET_ERROR)
			goto err;

		if (rv == 0)
			break;

		rv = recvfrom(sock, (char *)buf, sizeof(buf), 0, NULL, NULL);

		if (rv == SOCKET_ERROR)
			continue;

		mndppkt = parse_mndp(buf, rv);

		if (!mndppkt)
			continue;

		/* already seen */
		if (mndp_lookup(mndppkt->address))
			continue;

		mndphost = calloc_a(sizeof(*mndphost), &address, ETH_ALEN,
			&identity, mndppkt->identity ? 1 + strlen(mndppkt->identity) : 0,
			&platform, mndppkt->platform ? 1 + strlen(mndppkt->platform) : 0,
			&version,  mndppkt->version  ? 1 + strlen(mndppkt->version)  : 0,
			&hardware, mndppkt->hardware ? 1 + strlen(mndppkt->hardware) : 0,
			NULL);

		if (!mndphost)
			continue;

		mndphost->uptime  = mndppkt->uptime;
		mndphost->address = memcpy(address,  mndppkt->address, ETH_ALEN);

		if (mndppkt->identity)
			mndphost->identity = strcpy(identity, mndppkt->identity);

		if (mndppkt->platform)
			mndphost->platform = strcpy(platform, mndppkt->platform);

		if (mndppkt->version)
			mndphost->version  = strcpy(version,  mndppkt->version);

		if (mndppkt->hardware)
			mndphost->hardware = strcpy(hardware, mndppkt->hardware);

		list_add_tail(&mndphost->list, &mndphosts);
		found++;
	}

	closesocket(sock);

	return found;

err:
	if (sock != SOCKET_ERROR)
		closesocket(sock);

	return -1;
}

struct mndphost * mndp_lookup(const unsigned char *address)
{
	struct mndphost *host;

	list_for_each_entry(host, &mndphosts, list)
		if (!memcmp(host->address, address, ETH_ALEN))
			return host;

	return NULL;
}
