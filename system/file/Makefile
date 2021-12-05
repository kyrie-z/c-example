
CFLAGS = -Wall -O0
LIBS = -lcrypto 

build: attr

attr: main.c
	gcc ${CFLAGS} ${LIBS} -o $@ $^

clean:
	rm -rf attr