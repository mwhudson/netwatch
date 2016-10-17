# Build-Depends: libnl-route-3-dev

netwatch: netwatch.o Makefile
	gcc -g -O2 -o netwatch netwatch.o  -Wl,--no-as-needed `pkg-config --libs libnl-route-3.0` -Wl,--as-needed

netwatch.o: netwatch.c
	gcc -g -O2 -o netwatch.o -c netwatch.c `pkg-config --cflags libnl-route-3.0`
