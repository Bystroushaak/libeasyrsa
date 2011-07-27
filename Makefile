CC=gcc
CFLAGS=-c -I polarssl/include/
OUTPUT=libeasyrsa.a

build: $(OUTPUT)

$(OUTPUT): libeasyrsa.o
	#ar -cvq $(OUTPUT) rsa.o bignum.o md.o sha1.o
	gcc libeasyrsa.o polarssl/library/libpolarssl.a -otest

libeasyrsa.o: libeasyrsa.c libeasyrsa.h
	$(CC) $(CFLAGS) libeasyrsa.c -olibeasyrsa.o

clean:

run: build
	./test