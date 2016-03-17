## EZS library examples

noinst_PROGRAMS=client1 server1 crypt1 client2 client3 server2 server3
INCLUDES = -I..

# these seem to work on my linux and aix
AM_LDFLAGS= -L../.libs -L/usr/local/lib -lezs -lssl -lcrypto -lpthread -ldl

client1_SOURCES=client1.c
client2_SOURCES=client2.c
client3_SOURCES=client3.c
server1_SOURCES=server1.c
server2_SOURCES=server2.c
server3_SOURCES=server3.c
crypt1_SOURCES=crypt1.c

EXTRA_DIST= README 

