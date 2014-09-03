TOOLPATH?=/usr/bin/i586-mingw32msvc-

CC=$(TOOLPATH)gcc
AR=$(TOOLPATH)ar

CFLAGS+=-DWINVER=0x0500 -DPROGRAM_VERSION=\"git-$(shell git log -1 --format="%h" HEAD)\"
LIBS?=-L. -liphlpapi -lws2_32 -lplink


all: macssh.exe

clean:
	rm -f *.a *.o *.exe

distclean: clean
	rm -rf putty putty-src.zip

%.o: %.c
	$(CC) -Wall -I. $(CFLAGS) -o $@ -c $<

putty/windows/winplink.c:
	test -f putty-src.zip || \
		wget http://the.earth.li/~sgtatham/putty/latest/putty-src.zip

	mkdir -p putty
	unzip -o -L putty-src.zip -d putty

	#
	# remove deprecated "-mno-cygwin" flag and prevent actual linking
	#
	sed -i \
		-e 's#-mno-cygwin##g' \
		-e 's#$$(CC) $$(LDFLAGS)#true#g' \
			putty/windows/makefile.cyg

	#
	# patch putty sources
	#
	sed -i \
		-e 's#int main(#int plink_main(#g' \
			putty/windows/winplink.c

	sed -i \
		-e 's#\bexit(#ExitThread(#g' \
			putty/windows/wincons.c putty/windows/winplink.c

putty/windows/winplink.o: putty/windows/winplink.c
	TOOLPATH="$(TOOLPATH)" \
		$(MAKE) -C putty/windows -f makefile.cyg plink.exe

libplink.a: putty/windows/winplink.o
	$(AR) rcs $@ $(wildcard putty/windows/*.o)

macssh.exe: macssh.o protocol.o interfaces.o mndp.o pgetopt.o utils.o libplink.a
	$(CC) $(LDFLAGS) -o macssh.exe macssh.o protocol.o interfaces.o pgetopt.o utils.o mndp.o $(LIBS)
