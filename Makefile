# Build-Depends: libnl-route-3-dev

netwatch: netwatch.o
	gcc -g -O2 -o netwatch netwatch.o `pkg-config --libs libnl-route-3.0`

netwatch.o: netwatch.c
	gcc -g -O2 -o netwatch.o -c netwatch.c `pkg-config --cflags libnl-route-3.0`
