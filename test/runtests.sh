#!/bin/bash
#
# ezs tests

result=0

# basic encrypt / decrypt
echo "==== crypt test"
./crypt1 data/crypt1.txt crypt1.txt > crypt1.out
diff -q  data/crypt1.txt crypt1.txt
if [ $? -ne 0 ]; then ret=1; fi
diff -q  data/crypt1.out crypt1.out
if [ $? -ne 0 ]; then ret=1; fi
rm crypt1.txt crypt1.out


# basic client/server
echo "==== client/server test 1"
rm -f session.pem
rm -f server.out
rm -f client.out
rm -f client.err
# start server
./server1 -p 98765 -ca certs/ca.crt -c certs/server.crt -k certs/server.key -nt < /dev/null > server.out 2>&1 &
sleep 1
# test bad CA fails
echo "Hello, world. Fails by CA." | ./client1 -s localhost:98765 -ca certs/uwca.crt -c certs/client.crt -k  certs/client.key > client.out 2> client.err
# test new session
echo "Hello, world. First time.
Goodbye world." | ./client1 -s localhost:98765 -ca certs/ca.crt -c certs/client.crt -k  certs/client.key >> client.out 2>> client.err
# test recover session
echo "Hello, world. Second time.
exit" | ./client1 -s localhost:98765 -ca certs/ca.crt -c certs/client.crt -k  certs/client.key >> client.out 2>> client.err

diff -q  data/server1.out server.out
if [ $? -ne 0 ]; then ret=1; fi
diff -q  data/client1.out client.out
if [ $? -ne 0 ]; then ret=1; fi
diff -q  data/client1.err client.err
if [ $? -ne 0 ]; then ret=1; fi


# non-blocking server test
echo "==== client/server test 2"
rm -f session.pem
rm -f server.out
rm -f client.out
rm -f client.err
# start server
./server2 -p 98766 -ca certs/ca.crt -c certs/server.crt -k certs/server.key -nt < /dev/null > server.out 2>&1 &
sleep 1
# test new session
echo "Hello, world. First time.
Goodbye world." | ./client1 -s localhost:98766 -ca certs/ca.crt -c certs/client.crt -k  certs/client.key >> client.out 2>> client.err
# test recover session
echo "Hello, world. Second time.
exit" | ./client1 -s localhost:98766 -ca certs/ca.crt -c certs/client.crt -k  certs/client.key >> client.out 2>> client.err

diff -q  data/server2.out server.out
if [ $? -ne 0 ]; then ret=1; fi
diff -q  data/client2.out client.out
if [ $? -ne 0 ]; then ret=1; fi
diff -q  data/client2.err client.err
if [ $? -ne 0 ]; then ret=1; fi
rm -f session.pem


exit $ret
