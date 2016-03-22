## EZS library tests

noinst_PROGRAMS=server1 server2 client1 crypt1 test
.PHONY:	test
nodist_test_SOURCES = test
AM_CPPFLAGS = -I..

# these seem to work on my linux and aix
AM_LDFLAGS= -L../.libs -L/usr/local/lib -lezs -lssl -lcrypto -lpthread -ldl

crypt1_SOURCES=crypt1.c

EXTRA_PROGRAMS = test

test:	
	sh runtests.sh
