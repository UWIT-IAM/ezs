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
rm -f server1.out
rm -f client1.out
rm -f client1.err
# start server
./server1 -p 98765 -ca certs/cabundle.crt -c certs/server.crt -k certs/server.key -nt < /dev/null > server1.out 2>&1 &
sleep 1
# test bad CA fails
echo "Hello, world. Fails by CA." | ./client1 -s localhost:98765 -ca certs/uwca.crt -c certs/client.crt -k  certs/client.key > client1.out 2> client1.err
# test revokes cert fails
echo "Hello, world. Fails by revocation." | ./client1 -s localhost:98765 -ca certs/uwca.crt -c certs/client-r.crt -k  certs/client-r.key >> client1.out 2>> client1.err
# test new session
echo "Hello, world. First time.
Goodbye world." | ./client1 -s localhost:98765 -ca certs/ca.crt -c certs/client.crt -k  certs/client.key >> client1.out 2>> client1.err
# test recover session
echo "Hello, world. Second time.
exit" | ./client1 -s localhost:98765 -ca certs/ca.crt -c certs/client.crt -k  certs/client.key >> client1.out 2>> client1.err

diff -q  data/server1.out server1.out
if [ $? -ne 0 ]; then ret=1; fi
diff -q  data/client1.out client1.out
if [ $? -ne 0 ]; then ret=1; fi
diff -q  data/client1.err client1.err
if [ $? -ne 0 ]; then ret=1; fi


# non-blocking server test
echo "==== client/server test 2"
rm -f session.pem
rm -f server2.out
rm -f client2.out
rm -f client2.err
# start server
./server2 -p 98766 -ca certs/ca.crt -c certs/server.crt -k certs/server.key -nt < /dev/null > server2.out 2>&1 &
sleep 1
# test new session
echo "Hello, world. First time.
Goodbye world." | ./client1 -s localhost:98766 -ca certs/ca.crt -c certs/client.crt -k  certs/client.key >> client2.out 2>> client2.err
# test recover session
echo "Hello, world. Second time.
exit" | ./client1 -s localhost:98766 -ca certs/ca.crt -c certs/client.crt -k  certs/client.key >> client2.out 2>> client2.err

diff -q  data/server2.out server2.out
if [ $? -ne 0 ]; then ret=1; fi
diff -q  data/client2.out client2.out
if [ $? -ne 0 ]; then ret=1; fi
diff -q  data/client2.err client2.err
if [ $? -ne 0 ]; then ret=1; fi
rm -f session.pem


exit $ret
