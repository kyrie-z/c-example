
CC = gcc
CFLAGS = -Wall -g -O0
INCLUDE = -I./
SO = libursa.so
LIBS = -L./ -lcrypto -lursa


build: sv


sv: main.c ${SO}
	${CC} ${CFLAGS} ${INCLUDE} ${LIBS} -o $@ $<  

$(SO): u_rsa.c u_rsa.h
	${CC} ${CFLAGS} -shared -fPIC ${INCLUDE} -o $@ $^


clean:
	rm -rf sv *.so

.PHONY:clean sv
