CC=gcc
DC=dmd
CFLAGS=-c
LIBNAME=missing_obj.lib
CONV=obj_convertor.exe

build: stricmp.o $(CONV)
	./$(CONV)
	mv _chkstk.obj _divdi3.obj stricmp.obj ../

# http://www.koders.com/c/fid53CBD4D3D36D8CB24B74FD45E44456ECF0152255.aspx
# other object files are grabed from mingw-gcc
stricmp.o: stricmp.c
	$(CC) $(CFLAGS) $?

$(CONV): obj_convertor.d
	$(DC) $? -of$@

clean:
	-rm *.lib $(CONV) *.bak obj_convertor.obj
