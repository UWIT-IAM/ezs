/* ========================================================================
 * Copyright (c) 2006 The University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

#ifndef EZS_H
#define EZS_H

/* Definitions from configure. */

#define EZS_NAME "ezs"
#define EZS_VERSION_STRING "ezs 1.4.2"
#define EZS_VERSION "1.4.2"

/* end of configure generated data */


/* EZS library definitions */


#if defined(WIN32)
#include <windows.h>
#else
#include <sys/errno.h>
#endif 

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

extern int ezs_debug;   /* set nonzero for debug to stderr */

/* structure for certs and keys */

typedef struct EZSCert_ {
  struct EZSCert_ *next;
  char *cn;
  X509 *x;
  EVP_PKEY *k;
} EZSCert;

typedef struct EZSCrl_ {
  struct EZSCrl_ *next;
  char *cn;
  X509_CRL *x;
} EZSCrl;

typedef struct EZSCtx_ {
  struct EZSCtx_ *next;
  SSL_CTX *ssl_ctx;
  int ref_count;
} EZSCtx;


/* The EZS structure includes openssl structures */

typedef struct EZS_ {
   EZSCtx *ezs_ctx;
   BIO *conn;
   SSL *ssl;
   SSL_SESSION *session;
   char *peer_hn;      /* hostname of peer - if known */
   char *peer_cn;      /* CN from peer's cert */
   char *cipher_list;  /* List of available ciphers */
   int nonblocking;    /* use non-blocking io */
   int timeout;        /* timeout seconds for semi-blocking io */
   int reinit;         /* set to reinitialize on each crypt */
   int requir_peer_cn; /* do we reqyur the peer's cert name? */
   int verify_peer_cn; /* do we verify the peer's cert name? */
   int allow_v2;       /* do we allow sslv2? */
   int allow_v3;       /* do we allow sslv3? */
   EVP_CIPHER_CTX *ct[2]; /* cryption context */
   EVP_CIPHER *crypt_cipher;
   EVP_MD *crypt_hash;
   int ezs_errno;      /* per-connection errno */
   int read_waiton_read;
   int read_waiton_write;
   int write_waiton_read;
   int write_waiton_write;
   int connecting;     /* connect or accept in progress */
} EZS;

#define EZS_DEFAULT_TIMEOUT 30 /* 30 sec */

/* cryption */
#define EZS_ENCRYPT 1  /* EVP library conventions */
#define EZS_DECRYPT 0
#define EZS_BLOCKSIZE(E) EVP_CIPHER_CTX_block_size(E->ct[0])

/* errors */

#define EZS_ERR_NONE      0
#define EZS_ERR_SSL       1
#define EZS_ERR_PEERCRT   2
#define EZS_ERR_PEERCN    3
#define EZS_ERR_NOCRT     4
#define EZS_ERR_BADCRT    5
#define EZS_ERR_BADKEY    6

#define EZS_ERR_NO_CONNECTION     7
#define EZS_ERR_READ_WOULDBLOCK   8
#define EZS_ERR_WRITE_WOULDBLOCK  9
#define EZS_ERR_READ_EOF         10
#define EZS_ERR_WRITE_EOF        11

#define EZS_ERR_INVALID          12
#define EZS_ERR_CANT_HAPPEN      13
#define EZS_ERR_MAX              14

#ifdef _EZS_LIBRARY_
char *ezs_err_txt[] = {
  "No error",
  "SSL error",
  "Peer cert is invalid",
  "Peer cert cn does not match peer hostname",
  "Cert not found",
  "Certificate is invalid",
  "Key is invalid",
  "No connection",
  "Read would block",
  "Write would block",
  "Read end of file",
  "Write end of file",
  "Invalid arguments",
  "Can't happen"
};
#endif



/* exported procedures */

#define ezs_set_cipher_list(E,t) (E->cipher_list=strdup(t))
#define ezs_set_peer_hn(E,t) (E->peer_hn=t)
#define ezs_set_require(E,t) (E->requir_peer_cn=t)
#define ezs_set_verify(E,t) (E->verify_peer_cn=t)
#define ezs_set_timeout(E,t) (E->timeout=t)
#define ezs_use_nonblocking_io(E) (E->nonblocking=1)
#define ezs_use_blocking_io(E) (E->nonblocking=0)
#define ezs_allow_v2(E) (E->allow_v2=1)
#define ezs_allow_v3(E) (E->allow_v3=1)
#define ezs_deny_v2(E) (E->allow_v2=0)
#define ezs_deny_v3(E) (E->allow_v3=0)
#define ezs_load_rand_file(f) RAND_load_file(f,-1);
#define ezs_save_rand_file(f) RAND_write_file(f);

int ezs_errno(EZS *E);
int ezs_geterror(EZS *E, char **txt);
int ezs_wouldblock(EZS *E);

int ezs_init(char *name);
EZS *ezs_new();
void ezs_free(EZS *L);
char *ezs_version();
int ezs_add_ca(char *cafile);
int ezs_add_crl(char *crlfile);
int ezs_add_cert(char *crtfile, char *keyfile, char **cn);
char *ezs_get_peer_cn(EZS *E);


void ezs_set_session_name(char *name);
char *ezs_get_session(EZS *L);
int ezs_set_session(EZS *L, char *session);

int ezs_connect(EZS *L, char *service, char *cn);
int ezs_connect_fd(EZS *L, int fd, char *cn);
int ezs_disconnect(EZS *L);
int ezs_listen(EZS *L, char *port);
EZS *ezs_accept(EZS *A, char *cn);
int ezs_accept_fd(EZS *A, int fd, char *cn);
EZSCert *ezs_find_cert(char *cn);

int ezs_write(EZS *L, char *txt, int len);
int ezs_read(EZS *L, char *txt, int len);

int ezs_crypt_init(EZS *L, char *keytext, int keylen, unsigned char **iv);
int ezs_crypt(EZS *L, int mode, unsigned char *out, int *outlen, unsigned char *in, int inlen);

int ezs_hmac(unsigned char **h, int *hlp, unsigned char *data, int dl, unsigned char *key, int kl);
int ezs_data_to_base64(char **b64, int *bl, void *data, int dl);
int ezs_base64_to_data( void **data, int *dl, char *b64, int bl);


#endif /* EZS_H */
