TARGET = router

all: $(TARGET)

CC = gcc
LD = gcc

CFLAGS = -g -Wall -Iinclude
LDFLAGS =

LIBS = -lpthread

HDRS = ./include/*.h

SRCS = arp.c arpcache.c icmp.c ip.c ip_forwarding.c main.c packet.c rtable.c rtable_internal.c
OBJS = $(patsubst %.c,%.o,$(SRCS))

$(OBJS) : %.o : %.c include/*.h
	$(CC) -c $(CFLAGS) $< -o $@

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(TARGET) $(LIBS)

clean:
	rm -f *.o $(TARGET)

tags: $(SRCS) $(HDRS)
	ctags $(SRCS) $(HDRS)
