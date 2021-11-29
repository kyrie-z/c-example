
CC = gcc
CFLAGS = -Wall -g -O0
INCLUDE =
OBJS =
LIBS = -lcrypto

build: evp_cipher

evp_cipher: main.c
	${CC} ${CFLAGS} ${INCLUDE} -o $@ $^ ${OBJS} ${LIBS}

clean:
	rm -rf evp_cipher

.PHONY:clean
