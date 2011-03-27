OBJECTS=alt_buffer.o\
	buffer.o\
	codec.o\
	master.o\
	net.o\
	slave.o\
	util.o

all: heyoka
	$(CC) $(CFLAGS) main.c $(OBJECTS) -o heyoka -lpthread

heyoka: $(OBJECTS)

$(OBJECTS): %.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
	
clean:
	rm *.o
	rm heyoka
