
CC = gcc
CFLAGS = -Wall -g -O0
INCLUDE =
OBJS =
LIBS = -lcrypto

build: pkcs7-sign

pkcs7-sign: main.c
	${CC} ${CFLAGS} ${INCLUDE} -o $@ $^ ${OBJS} ${LIBS}

clean:
	rm -rf pkcs7-sign

.PHONY:clean
