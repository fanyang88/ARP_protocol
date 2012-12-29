CC = gcc

LIBS =  /home/users/cse533/Stevens/unpv13e/libunp.a

# CFLAGS = -g -O2 -Wall -I /home/users/cse533/Stevens/unpv13e/lib/
CFLAGS = -g -O2 -I /home/users/cse533/Stevens/unpv13e/lib/

all: tour_g18 arp_g18

tour_g18: tour.o ping.o get_hw_addrs.o 
	${CC} -o tour_g18 tour.o ping.o get_hw_addrs.o ${LIBS}

tour.o: tour.c tour.h
	${CC} ${CFLAGS} -c tour.c

ping.o: ping.c tour.h
	${CC} ${CFLAGS} -c ping.c

mcast.o: mcast.c tour.h
	${CC} ${CFLAGS} -c mcast.c

arp_g18: arp.o get_hw_addrs.o
	${CC} -o arp_g18 arp.o get_hw_addrs.o ${LIBS}

arp.o: arp.c
	${CC} ${CFLAGS} -c arp.c

prhwaddrs: get_hw_addrs.o prhwaddrs.o
	${CC} -o prhwaddrs prhwaddrs.o get_hw_addrs.o ${LIBS}

get_hw_addrs.o: get_hw_addrs.c
	${CC} ${CFLAGS} -c get_hw_addrs.c

prhwaddrs.o: prhwaddrs.c
	${CC} ${CFLAGS} -c prhwaddrs.c

clean:
	rm tour_g18 arp_g18 *.o

