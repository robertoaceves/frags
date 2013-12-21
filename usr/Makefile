
EXEC = frags
SOURCES = frags.c configuration.c str_utils.c netlink.c communication.c parameters.c
SOURCES += network_utils.c layer_network.c layer_transport.c layer_payload.c
OBJS = $(SOURCES:.c=.o)
#SRCDIR = src 
#BINDIR = bin

CC = gcc
CFLAGS += -Wall
CFLAGS += -g 			# Debug
#CFLAGS += -pedantic  	# Maybe
CFLAGS += -I/usr/include/libnl3 	# Netlink headers
LDFLAGS = -lnl-3

all: ${EXEC}

${EXEC}: ${OBJS}
	$(CC) $(OBJS) $(LDFLAGS) -o $@
	
#.c.o:
#%.o:%.c
#	$(CC) $(CFLAGS) $< -o $@

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

#frags.o: frags.c
#	$(CC) $(CFLAGS) ${SRCDIR}/$< -o ${SRCDIR}/$@

clean:
	rm -f *.o ${EXEC}
