CC = gcc
CFLAGS = -Wall -g
INCLUDE = public.h

build: server client

server: server.c
	${CC} ${CFLAGS} ${INCLUDE} -o $@ $^ 

client: client.c
	${CC} ${CFLAGS} ${INCLUDE} -o $@ $^ 

clean:
	rm server client public.gch -rf
