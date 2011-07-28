CC=gcc
CFLAGS=-c -I polarssl/include/
OUTPUT=libeasyrsa.a

build: $(OUTPUT)

$(OUTPUT): easyrsa.o
	(cd polarssl; make)
	@echo
	@echo Creating library $(OUTPUT):
	-mkdir out
	ar -rcs out/$(OUTPUT) easyrsa.o
	cp polarssl/library/*.a out
	cp easyrsa.d easyrsa.h out
	
	@echo
	@echo Success

easyrsa.o: easyrsa.c easyrsa.h
	$(CC) $(CFLAGS) easyrsa.c -oeasyrsa.o

clean:
	-rm *.a *.o
	
download:
	svn co http://polarssl.org/repos/polarssl/polarssl/trunk polarssl

help:
	@echo download
	@echo "	Download fresh polarss from repository."
	@echo build
	@echo "	Build library (also polarssl)."
	@echo clean
	@echo "	Remove all object files and library." 
	@echo help
	@echo "	Print this help."
