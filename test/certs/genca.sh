
# gen the ca cert
openssl req -x509 -config ca.cnf -newkey rsa:4096 -sha256 -nodes -out ca.crt -outform PEM -keyout ca.key

# server cert req
openssl req -config req.cnf -newkey rsa:2048 -sha256 -nodes -out server.req -outform PEM -keyout server.key

# cert sign
openssl ca -config ca.cnf -policy signing_policy -extensions signing_req -out server.crt -infiles server.req

# client cert req
openssl req -config req.cnf -newkey rsa:2048 -sha256 -nodes -out client.req -outform PEM -keyout client.key

# cert sign
openssl ca -config ca.cnf -policy signing_policy -extensions signing_req -out client.crt -infiles client.req
