MAC SSH client for Windows
==============================

This is a MAC-SSH client for Windows based on
[MAC-Telnet](https://github.com/aouyar/MAC-Telnet) from
[aouyar](https://github.com/aouyar) (_Ali Onur Uyar_) which is an SSH-enabled
version of the original MAC-Telnet implementation from
[haakonnessjoen](https://github.com/haakonnessjoen) (_Håkon Nessjøen_).

The code handles the layer 2 UDP connection and MNDP discovery portion of the
MAC-Telnet protocol to allow tunneling SSH connections to an SSH enabled
MAC-Telnet server.

SSH support is provided by an embedded copy of the PuTTY "plink.exe" utility.

Parts of the code are taken from the 
[OpenWrt libubox project](http://git.openwrt.org/?p=project/libubox.git).

Command line processing is provided by a portable variant of a free IBM getopt()
implementation, see pgetopt.c for licensing details.


Licensing
---------

See the _LICENSE_ file for licensing information on the MAC-SSH code in
macssh.c, protocol.c, interfaces.c and mndp.c .

The libubox routines in utils.c are available under a MIT style license, see
the source file for details.

Portable getopt is provided as-is and free of use, see pgetopt.c for details.


Building
--------

Compiling MAC-SSH has been tested on Debian 7 using the "gcc-mingw32" package.
If you intend to build it on other distributions or with other variants of the
MinGW toolchain you might need to change the TOOLPATH variable in Makefile to
suit your needs.

To build MAC-SSH clone the sources and execute "make" - the resulting
"macssh.exe" utility will be placed in the same directory.

Make will fetch, modify and compile PuTTY as part of the build process, this
requires GNU wget and GNU sed on the build system.


Download
--------

You can find a precompiled version of "macssh.exe" on
[subsignal.org](http://luci.subsignal.org/~jow/mac-ssh-win32/).
