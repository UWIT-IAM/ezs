/* ========================================================================
 * Copyright (c) 2006-2014 The University of Washington
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

/* EZ-SSL library.
   See: http://staff.washington.edu/fox/ezs/
 */


#include <assert.h>

#ifdef WIN32
#include <winsock2.h>
#include <wincrypt.h>
#define strcasecmp _stricmp
#define strdup _strdup
#define HAVE_CONFIG_H
#else
#include <sys/ioctl.h>
#include <signal.h>
#endif


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _EZS_LIBRARY_
#include "ezs.h"
#include "ezsthread.h"

int ezs_debug = 0;  /* client can set to 1 for debug output to stderr */
#ifndef DEBUG_FP
#define DEBUG_FP stderr
#endif
#define FPRINTF if(ezs_debug)fprintf


/* A few static variables to hold info for all connections 
   These allow us to share default settings between multiple connections.
*/

static EZSCtx *ezs_ctx = NULL;            /* active context */
static EZSCert *ezs_cert_list = NULL;     /* list of certs */
static EZSCert *ezs_ca_list = NULL;       /* list of ca certs */
static EZSCrl *ezs_crl_list = NULL;       /* list of crls */
/* all of above lists use this lock */
MUTEX_T ezs_ctx_lock;

static const EVP_CIPHER *(*crypt_cipher)() = NULL;
static const EVP_MD *(*crypt_hash)() = NULL;

static int ezs_global_errno;                /* non-'EZS*' errors */
static unsigned char *session_name = NULL;  /* non-null means server uses sessions */
static char *randfile = NULL;

#define INVALID(r) {ezs_global_errno = EZS_ERR_INVALID;return (r);}
#define INVALID_E(e,r) {e->ezs_errno = EZS_ERR_INVALID;return (r);}

static int need_init = 1;
#define EZS_INIT {if (need_init) ezs_init(NULL);}
const char *EZS_version_str = PACKAGE_STRING;


/* ---------- internal procedures ------------------ */

/* malloc and free with error check */

static void *MALLOC(int nb)
{
   char *m = (char*) malloc(nb);
   assert(m!=NULL);
   return (m);
}

static void FREE(void *m) 
{
   if (m) free(m);
}
   
static void *STRDUP(char *s)
{
   char *m = s?strdup(s):NULL;
   return (m);
}

/* Minimal randomness - caller should use load_rand_file */

static void add_bit_of_randomness()
{
#ifdef WIN32
   FILETIME ft;
   GetSystemTimeAsFileTime(&ft);
   RAND_seed(&ft.dwLowDateTime, 8);
#else
   struct timeval tv;
   gettimeofday(&tv,NULL);
   RAND_seed(&tv.tv_usec, 4);
#endif
}

/* Display a cert error if debugging. 
   Callback from openssl  */

static int verify_callback(int ok, X509_STORE_CTX *store)
{
   char data[256];

   if (ezs_debug && !ok) {
      X509 *cert = X509_STORE_CTX_get_current_cert(store);
      int d = X509_STORE_CTX_get_error_depth(store);
      int err = X509_STORE_CTX_get_error(store);
      X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
      FPRINTF(DEBUG_FP, "cert verify: d=%d, dn=%s, err=%d %s\n", d, data,
         err, X509_verify_cert_error_string(err));
   }
   return (ok);
}

/* Context procedures.  The ssl context holds many defaults
   and 'globals' for an ssl connection, including the ca and
   crl used to authenticate peers.  We cannot edit an in-use
   context.  So to update a CRL we must create a new one.
   */

/* Make a new context. Caller has ezs_ctx_lock. */
static EZSCtx *ezs_ctx_new(int flags)
{
   EZSCtx *ctx;
   EZSCert *crt;
   EZSCrl *crl;
   X509_STORE *store;
   int i;

   FPRINTF(DEBUG_FP, "creating a context\n");
   ctx = (EZSCtx*) MALLOC(sizeof(EZSCtx));
   ctx->ref_count = 0;

   ctx->ssl_ctx = SSL_CTX_new(SSLv23_method());
   SSL_CTX_set_default_verify_paths(ctx->ssl_ctx);
   SSL_CTX_set_verify(ctx->ssl_ctx, flags, verify_callback);

   /* add CA list */
   store = SSL_CTX_get_cert_store(ctx->ssl_ctx);
   for (crt=ezs_ca_list; crt; crt = crt->next) {
       FPRINTF(DEBUG_FP, "adding ca: %s\n", crt->cn);
       i = X509_STORE_add_cert(store, crt->x);
       if (!i) {
          FPRINTF(DEBUG_FP, "addca failed at %s, %d\n", crt->cn, i);
          /* return (NULL);   let it be */
       }
   }

   /* add crl list */
   for (crl=ezs_crl_list; crl; crl = crl->next) {
       FPRINTF(DEBUG_FP, "adding crl for %s\n", crl->cn);
       i = X509_STORE_add_crl(store, crl->x);
       if (!i) {
          FPRINTF(DEBUG_FP, "addcrl failed at %s, %d\n", crl->cn, i);
          /* return (NULL); */
       }
   }
   if (ezs_crl_list) X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
 
   /* server session name */
   if (session_name) SSL_CTX_set_session_id_context(ctx->ssl_ctx, session_name, (int)strlen((char*)session_name));
   else SSL_CTX_ctrl(ctx->ssl_ctx, SSL_CTRL_SET_SESS_CACHE_MODE, SSL_SESS_CACHE_OFF, NULL);

   return (ctx);
}


static EZSCtx *get_ezs_ctx(int flags)
{
   EZSCtx *ret = NULL;
   FPRINTF(DEBUG_FP, "getting a context\n");
   MUTEX_LOCK(ezs_ctx_lock);
   if (!ezs_ctx) ezs_ctx = ezs_ctx_new(flags);
   if (ezs_ctx) {
      ret = ezs_ctx;
      ret->ref_count++;
   }
   MUTEX_UNLOCK(ezs_ctx_lock);
   return (ret);
}

static void free_ezs_ctx(EZSCtx *ctx)
{
   if (ctx->ssl_ctx) SSL_CTX_free(ctx->ssl_ctx);
   FREE(ctx);
}

static void release_ezs_ctx(EZSCtx *ctx)
{
   FPRINTF(DEBUG_FP, "releasing a context, count=%d, current=%s\n", ctx->ref_count, ctx==ezs_ctx?"yes":"no");
   MUTEX_LOCK(ezs_ctx_lock);
   ctx->ref_count--;
   if (ctx!=ezs_ctx) {
      if (ctx->ref_count<=0) {
         FPRINTF(DEBUG_FP, " .. not current and unused, will free\n");
         free_ezs_ctx(ctx);
      }
   }
   MUTEX_UNLOCK(ezs_ctx_lock);
}

/* shutdown and clear a connection */
static void do_shutdown(EZS *E)
{
   int max;
   if (!E) return;

   FPRINTF(DEBUG_FP, "shutdown connection\n");
 
   if (E->conn) {
      for (max=0;max<10;max++) {
         int i;
         i=(int)BIO_flush(E->conn);
         FPRINTF(DEBUG_FP, " .. tried flush (%d)\n", i);
         if (i <= 0) {
            if (!BIO_should_retry(E->conn)) break;
         } else {
            break;
         }
      }
   }

   if (E->ssl) {
      SSL_set_shutdown(E->ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
      SSL_free(E->ssl);
   }

   if (E->ezs_ctx) release_ezs_ctx(E->ezs_ctx);

   E->ssl = NULL;
   E->conn = NULL;
   E->ezs_ctx = NULL;
}

/* Check cert name, pattern can be: '*.aaa.bbb' etc. 
   Return 1 if match OK */

static int check_name(char *pat, char *name)
{
   char c;
   while (1) {
      c = *pat++;
      if (!c) return ((*name)?0:1);
      if (c=='*') {
         if (!*pat) return (1);
         while (*name) if(check_name(name++, pat)) return (1);
         return (0);
      }
      if (toupper(c) != toupper(*(name++))) return (0);
   }
}

/* If verifying, check that the cert name matches the host name.
   Also set peer_cn.
   Return 1 if OK. */

static int check_peer(EZS *E)
{
   X509 *peercert;
   char cn[256];
   STACK_OF(GENERAL_NAME) *altnams;
   int i, na, r;
    
   if ((r=SSL_get_verify_result(E->ssl))!=X509_V_OK) {
      E->ezs_errno = EZS_ERR_PEERCRT;
      return (0);
   }
      
   peercert = SSL_get_peer_certificate(E->ssl);
   if (!peercert) {
      E->peer_cn = STRDUP("anonymous");
      return(1);
   }

   cn[0] = 0;
   X509_NAME_get_text_by_NID (X509_get_subject_name(peercert), NID_commonName, cn, 256);

   E->peer_cn = STRDUP(cn);

   /* If there's no hostname, or we're not verifying, return OK now */

   if ((!E->peer_hn) || (!E->verify_peer_cn)) {
      X509_free(peercert);
      return (1);
   }

   /* Else check altnames first */

   altnams = X509_get_ext_d2i(peercert, NID_subject_alt_name, NULL, NULL);
   na = sk_GENERAL_NAME_num(altnams);
   for (i=0; i<na; i++) {
      char *altn;
      GENERAL_NAME *ck = sk_GENERAL_NAME_value(altnams, i);
      if (ck->type != GEN_DNS) continue;
      altn = (char *)ASN1_STRING_data(ck->d.ia5);
      if (check_name(altn, E->peer_hn)) break;
   }
   GENERAL_NAMES_free(altnams);

   X509_free(peercert);
   
   if (i<na) return (1); /* name ok */

   if (na>0) {  /* RFC2459: altnames must be used if present */
      if (!strcasecmp(cn,E->peer_hn)) return (1);
   }
   E->ezs_errno = EZS_ERR_PEERCN;
   return (0);
}

/* Get the CN from a cert */

static char *get_cn_from_cert(X509 *x)
{
   char cn[256];
   int r;
   r = X509_NAME_get_text_by_NID (X509_get_subject_name(x), NID_commonName, cn, 256);
   return (STRDUP(r != -1 ? cn : "-N/A-"));
}



/* Set the cert to use for authentication.
   Return 1 if OK */

static int set_ssl_cert(EZS *E, char *cn)
{
   EZSCert *c = ezs_find_cert(cn);
   int r;

   if (!c) {
      E->ezs_errno = EZS_ERR_NOCRT;
      return (0);
   }
   if (!E->ssl) {
      E->ezs_errno = EZS_ERR_NO_CONNECTION;
      return (0);
   }
 
   if ((r=SSL_use_certificate(E->ssl, c->x)) != 1) {
      E->ezs_errno = EZS_ERR_BADCRT;
      return (0);
   }
   if ((r=SSL_use_PrivateKey(E->ssl, c->k)) != 1) {
      E->ezs_errno = EZS_ERR_BADKEY;
      return (0);
   }
   return (1);
}


/* Establish an SSL connection using an existing BIO.
   Return: 1 on OK
 */

static int connect_bio(EZS *E, char *cn)
{
   int sl = 1;
   int r;

   int fd;
   fd_set rfds, wfds;
   struct timeval wait;
   int wblock, rblock;

   if (!E) return (0);

   wait.tv_sec = E->timeout;
   wait.tv_usec = 0;
   FD_ZERO(&rfds);
   FD_ZERO(&wfds);
   E->ezs_errno = 0;

   FPRINTF(DEBUG_FP,"connect starting (%d)\n", E->connecting);

   if (!E->connecting) {

      /* first time - do initialization */

      E->ezs_ctx = get_ezs_ctx(E->requir_peer_cn ? SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT : SSL_VERIFY_PEER);
      if (!E->ezs_ctx) {
         E->ezs_errno = EZS_ERR_SSL;
         return (0);
      }
      E->ssl = SSL_new(E->ezs_ctx->ssl_ctx);
      if (!E->ssl) {
         E->ezs_errno = EZS_ERR_SSL;
         return (0);
      }
      if (E->cipher_list) SSL_set_cipher_list(E->ssl, E->cipher_list);
      SSL_set_bio(E->ssl, E->conn, E->conn);

      if (!set_ssl_cert(E, cn)) return (0);

      if (E->session) {
         FPRINTF(DEBUG_FP, "using saved session\n");
         SSL_set_session(E->ssl, E->session);
         SSL_SESSION_free(E->session);
      }

      if (!E->allow_v2) SSL_set_options(E->ssl, SSL_OP_NO_SSLv2);
      if (!E->allow_v3) SSL_set_options(E->ssl, SSL_OP_NO_SSLv3);

      /* set non-blocking */
#ifdef FIONBIO
      if (E->nonblocking) {
         FPRINTF(DEBUG_FP,"will use non-blocking io\n");
         if (BIO_socket_ioctl(SSL_get_fd(E->ssl),FIONBIO,&sl) < 0) {
            E->ezs_errno = EZS_ERR_SSL;
            return (0);
         }
      } else {
         FPRINTF(DEBUG_FP,"will use blocking io\n");
      }
#endif

   }

   fd = SSL_get_fd(E->ssl);

   for (;;) {   /* try to connect */

      int connect_ok = 0;
      rblock = 0;
      wblock = 0;

      r = SSL_connect(E->ssl);
      FPRINTF (DEBUG_FP, "connect ret: %d\n", SSL_get_error(E->ssl, r));

      switch (SSL_get_error(E->ssl, r)) {

         case SSL_ERROR_NONE:   /* connect OK */
             connect_ok = 1;
             break;

         case SSL_ERROR_ZERO_RETURN:  /* eof */
             E->ezs_errno = EZS_ERR_READ_EOF;
             return (0);

         case SSL_ERROR_WANT_READ:   /* renegotation in progress probably */
             FD_SET(fd, &rfds);
             rblock = 1;
             break;

         case SSL_ERROR_WANT_WRITE:  /* record not completely written */
             FD_SET(fd, &wfds);
             wblock = 1;
             break;

         default:
             E->ezs_errno = EZS_ERR_SSL;
             return (0);

     }

     if (connect_ok) break;

     /* not done yet */

#ifdef FIONBIO

     FPRINTF(DEBUG_FP,"connect incomplete ... \n");
     E->connecting = 1;

     if (E->timeout<=0) {
        E->ezs_errno = rblock? EZS_ERR_READ_WOULDBLOCK: EZS_ERR_WRITE_WOULDBLOCK;
        return (0);
     }

     /* retry for semi-block time */
     r = select(fd+1, &rfds, &wfds, NULL, &wait);

     /* see if a read block is over */
     if (rblock) {
        if (FD_ISSET(fd, &rfds)) {
            continue;
        }
        E->ezs_errno = EZS_ERR_READ_WOULDBLOCK;
        return (0);
     }

     /* see if a write block is over */
     if (wblock) {
        if (FD_ISSET(fd, &wfds)) {
            continue;
        }
        E->ezs_errno = EZS_ERR_WRITE_WOULDBLOCK;
        return (0);
     }

     /* don't think we get WANT_CONNECT here */
#else 
     return (0); /* ? */
#endif

   }

   FPRINTF(DEBUG_FP,"connection established \n");

   if (!check_peer(E)) {
      return (0);
   }

   E->session = SSL_get1_session(E->ssl);

   return (1);
}


/* Establish SSL on an accepted BIO.
   Return: 1 on OK
*/

static int accept_bio(EZS *E, char *cn)
{
   int sl = 1;
   int r;

   int fd;
   fd_set rfds, wfds;
   struct timeval wait;
   int wblock, rblock;

   if (!E) return (0);

   wait.tv_sec = E->timeout;
   wait.tv_usec = 0;
   FD_ZERO(&rfds);
   FD_ZERO(&wfds);
   E->ezs_errno = 0;

   FPRINTF(DEBUG_FP,"accept starting (%d)\n", E->connecting);

   if (!E->connecting) {

      E->ezs_ctx = get_ezs_ctx(E->requir_peer_cn ? SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT : SSL_VERIFY_PEER);
      if (!E->ezs_ctx) {
         E->ezs_errno = EZS_ERR_SSL;
         return (0);
      }
      E->ssl = SSL_new(E->ezs_ctx->ssl_ctx);
      if (!E->ssl) {
         E->ezs_errno = EZS_ERR_SSL;
         return (0);
      }
  
      if (E->cipher_list) SSL_set_cipher_list(E->ssl, E->cipher_list);
      SSL_set_bio(E->ssl, E->conn, E->conn);
      SSL_set_accept_state(E->ssl);

      if (!set_ssl_cert(E, cn)) {
         E->ezs_errno = EZS_ERR_SSL;
         return (0);
      }
      if (!E->allow_v2) SSL_set_options(E->ssl, SSL_OP_NO_SSLv2);
      if (!E->allow_v3) SSL_set_options(E->ssl, SSL_OP_NO_SSLv3);

      /* set non-blocking */
#ifdef FIONBIO
      if (E->nonblocking) {
         FPRINTF(DEBUG_FP,"will use non-blocking io\n");
         if (BIO_socket_ioctl(SSL_get_fd(E->ssl),FIONBIO,&sl) < 0) {
            E->ezs_errno = EZS_ERR_SSL;
            return (0);
         }
      } else {
         FPRINTF(DEBUG_FP,"will use blocking io\n");
      }
#endif

   } 

   fd = SSL_get_fd(E->ssl);

   for (;;) {

     int accept_ok = 0;
    
     rblock = 0;
     wblock = 0;

     r = SSL_accept(E->ssl);
     FPRINTF (DEBUG_FP, "accept ret: %d\n", SSL_get_error(E->ssl, r));

     switch (SSL_get_error(E->ssl, r)) {
     
         case SSL_ERROR_NONE:   /* accept OK */
             accept_ok = 1;
             break;

         case SSL_ERROR_ZERO_RETURN:  /* eof */
             E->ezs_errno = EZS_ERR_WRITE_EOF;
             return (0);

         case SSL_ERROR_WANT_READ:   /* renegotation in progress probably */
             FD_SET(fd, &rfds);
             rblock = 1;
             break;

         case SSL_ERROR_WANT_WRITE:  /* record not completely written */
             FD_SET(fd, &wfds);
             wblock = 1;
             break;
      
         default:
             E->ezs_errno = EZS_ERR_SSL;
             return (0);

     }

     if (accept_ok) break;

     /* not done yet */

#ifdef FIONBIO

     FPRINTF(DEBUG_FP,"accept incomplete... \n");
     E->connecting = 1;

     if (E->timeout<=0) {
        E->ezs_errno = rblock? EZS_ERR_READ_WOULDBLOCK: EZS_ERR_WRITE_WOULDBLOCK;
        return (0);
     }
     
     /* retry for semi-block time */
     r = select(fd+1, &rfds, &wfds, NULL, &wait);

     /* see if a read block is over */
     if (rblock) {
        if (FD_ISSET(fd, &rfds)) {
            continue;
        }
        E->ezs_errno = EZS_ERR_READ_WOULDBLOCK;
        return (0);
     }

     /* see if a write block is over */
     if (wblock) {
        if (FD_ISSET(fd, &wfds)) {
            continue;
        }
        E->ezs_errno = EZS_ERR_WRITE_WOULDBLOCK;
        return (0);
     }

     /* don't think we get WANT_ACCEPT here */
#else 
     return (0); /* ? */
#endif

   }

   FPRINTF(DEBUG_FP,"accept complete \n");
   
   E->connecting = 0;

   if (!check_peer(E)) {
      return (0);
   }

   return (1);
}

/* ------------- public interfaces --------------------- */


/* Error retrieval */

int ezs_errno(EZS *E) 
{
   if (E) return (E->ezs_errno);
   return (ezs_global_errno);
}

/* Find a cert by cn */

EZSCert *ezs_find_cert(char *cn)
{
   EZSCert *c;
   if (!cn) return(ezs_cert_list);
   for (c=ezs_cert_list; c; c=c->next) if (!strcasecmp(c->cn, cn)) return (c);
   return (NULL);
}

#define EZSERRL 2048
int ezs_geterror(EZS *E, char **errtxtret) 
{
   int err;
   char *errtxt;
   char *etp;
   int etl;
   unsigned long sslerr;

   if (E) err = E->ezs_errno;
   else err = ezs_global_errno;

   if (errtxtret) {
      errtxt = (char*) MALLOC(EZSERRL);
      if (err<0) strncpy(errtxt, strerror(0-err), EZSERRL);
      else if (err>=0&&err<EZS_ERR_MAX) strncpy(errtxt, ezs_err_txt[err], EZSERRL);
      else errtxt[0] = '\0';
      /* add any ssl errors */
      for (etp=errtxt, etl=1; *etp; etp++,etl++);
      while (sslerr = ERR_get_error()) {
         *etp++ = '\n';
         etl++;
         ERR_error_string_n(sslerr, etp, EZSERRL-etl);
         for (; *etp; etp++,etl++);
      }
      *errtxtret = errtxt;
   }
   return (err);
}
         
/* return true if the last error was a wouldblock */
int ezs_wouldblock(EZS *E)
{
   return((E->ezs_errno==EZS_ERR_READ_WOULDBLOCK) || (E->ezs_errno==EZS_ERR_WRITE_WOULDBLOCK));
}


/* Initialize the library and openssl.  
   'name' is the session name (for servers).
   Return 1 on OK
   */

int ezs_init(char *name)
{
   add_bit_of_randomness();

   if (need_init) {         /* one-time run-time init */

      ezs_ctx = NULL;
      ezs_cert_list = NULL;
      ezs_ca_list = NULL;
      ezs_crl_list = NULL;
      if (!crypt_cipher) crypt_cipher = EVP_aes_128_cbc;  /* AES in CBC mode */
      if (!crypt_hash) crypt_hash = EVP_sha1; /* SHA1 */
      
      ezs_global_errno = 0;
      /* Only do thread setup if no one else has */
      if (CRYPTO_get_locking_callback()==NULL) {
         ezs_THREAD_setup();
      }
      MUTEX_SETUP(ezs_ctx_lock);
      SSL_load_error_strings();
      SSL_library_init();

#if defined(SIGPIPE)
      signal(SIGPIPE, SIG_IGN);
#endif

      need_init = 0;

   }

   add_bit_of_randomness();

   /* set the session name (for servers) */

   if (name) session_name = (unsigned char*) STRDUP(name);
   else session_name = NULL;

   return (1);
}

/* EZS version info */

char *ezs_version()
{
   size_t l = strlen(EZS_VERSION_STRING) + strlen(OPENSSL_VERSION_TEXT) + 64;
   char *v = (char*) malloc(l);
   sprintf(v, "%s (Openssl: %s)", EZS_VERSION_STRING, OPENSSL_VERSION_TEXT);
   return (v);
}

/* Create an ezs. */

EZS *ezs_new()
{
   EZS *E;

   EZS_INIT;

   E = (EZS*) MALLOC(sizeof(EZS));
   memset (E, '\0', sizeof(EZS));
   E->requir_peer_cn = 1;
   E->timeout = EZS_DEFAULT_TIMEOUT;
   E->allow_v3 = 1;  // default - due to history
   return (E);
}

/* free an ezs */

void ezs_free(EZS *E)
{
   if (!E) return;

   do_shutdown(E);
   if (E->session) SSL_SESSION_free(E->session);
   FREE(E->peer_cn);
   FREE(E->peer_hn);
   FREE (E);
}

/* Set session name.  */

void ezs_set_session_name(char *name)
{
   EZS_INIT;

   MUTEX_LOCK(ezs_ctx_lock);
   if (session_name) FREE(session_name);
   if (name) session_name = STRDUP(name);
   else session_name = NULL;
   if (ezs_ctx && ezs_ctx->ref_count<=0) free_ezs_ctx(ezs_ctx);
   ezs_ctx = NULL;
   MUTEX_UNLOCK(ezs_ctx_lock);
}

/* Add a CA to our list to use for verification */

int ezs_add_ca(char *cafile)
{
   X509 *x;
   FILE *fp;
   EZSCert *ca;

   EZS_INIT;

   if (!(fp=fopen(cafile, "r"))) {
      ezs_global_errno = 0 - errno;
      return (0);
   }

   while ((x = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
      ca = (EZSCert*) MALLOC(sizeof(EZSCert));
      ca->x = x;
      ca->k = NULL;
      ca->cn = get_cn_from_cert(x);
      FPRINTF(DEBUG_FP, " .. adding ca %s\n", ca->cn);

      MUTEX_LOCK(ezs_ctx_lock);
      ca->next = ezs_ca_list;
      ezs_ca_list = ca;
      /* additions to ca list require new context */
      if (ezs_ctx && ezs_ctx->ref_count<=0) free_ezs_ctx(ezs_ctx);
      ezs_ctx = NULL;
      MUTEX_UNLOCK(ezs_ctx_lock);
   }

   fclose(fp);
   if (!ezs_ca_list) {
      ezs_global_errno = EZS_ERR_SSL;
      return (0);
   }

   /* also add any crl info in the ca file */
   ezs_add_crl(cafile);
   return (1);
}

/* Add a CRL to use for verification */

int ezs_add_crl(char *crlfile)
{
   X509_CRL *x;
   FILE *fp;
   EZSCrl *crl;
   EZSCrl *c, *pc;

   EZS_INIT;

   if (!(fp=fopen(crlfile, "r"))) {
      ezs_global_errno = 0 - errno;
      return (0);
   }
   while ((x = PEM_read_X509_CRL(fp, NULL, NULL, NULL)) != NULL) {
      crl = (EZSCrl*) MALLOC(sizeof(EZSCrl));
      crl->x = x;
      crl->cn = X509_NAME_oneline(crl->x->crl->issuer, NULL, 0);
      FPRINTF(DEBUG_FP, " .. adding crl %s\n", crl->cn);

      /* Add this crl to the list, might have to replace an existing one */
      MUTEX_LOCK(ezs_ctx_lock);
      for (pc=NULL,c=ezs_crl_list; c; pc=c,c=c->next) {
         if (!X509_CRL_cmp(c->x, crl->x)) {
            FPRINTF(DEBUG_FP, " .. is duplicate, unlinking old\n");
            if (pc) pc->next = c->next;
            else ezs_crl_list = c->next;
            X509_CRL_free(c->x);
            FREE(c->cn);
            FREE(c);
            break;
         }
       }
      crl->next = ezs_crl_list;
      ezs_crl_list = crl;
      /* changes to crl list require new context */
      if (ezs_ctx && ezs_ctx->ref_count<=0) free_ezs_ctx(ezs_ctx);
      ezs_ctx = NULL;
      MUTEX_UNLOCK(ezs_ctx_lock);
    }
   fclose(fp);
   if (!ezs_crl_list) {
      ezs_global_errno = EZS_ERR_SSL;
      return (0);
   }

   return (1);
}

/* Get peer cn */

char *ezs_get_peer_cn(EZS *E)
{
   return (E?E->peer_cn:NULL);
}

/* Add a cert and key to a context's cert list */

int ezs_add_cert(char *crtfile, char *keyfile, char **cn)
{
   X509 *x;
   EVP_PKEY *k;
   FILE *fp1, *fp2;
   EZSCert *ce;

   EZS_INIT;

   if (!(fp1=fopen(crtfile, "r"))) {
      ezs_global_errno = 0 - errno;
      return (0);
   } else if (!(fp2=fopen(keyfile?keyfile:crtfile, "r"))) {
      fclose(fp1);
      ezs_global_errno = EZS_ERR_SSL;
      return (0);
   }

   while ((x = PEM_read_X509(fp1, NULL, NULL, NULL)) != NULL) {
      k = PEM_read_PrivateKey(fp2, NULL, NULL, NULL);
      if (!k) {
         X509_free(x);
         fclose(fp1);
         fclose(fp2);
         ezs_global_errno = EZS_ERR_SSL;
         return (0);
      }
      ce = (EZSCert*) MALLOC(sizeof(EZSCert));
      ce->x = x;
      ce->k = k;
      ce->cn = get_cn_from_cert(x);
      if (cn && !*cn) *cn = STRDUP(ce->cn);

      MUTEX_LOCK(ezs_ctx_lock);
      ce->next = ezs_cert_list;
      ezs_cert_list = ce;
      MUTEX_UNLOCK(ezs_ctx_lock);
   }

   fclose(fp1);
   fclose(fp2);
   if (!ezs_cert_list) {
      ezs_global_errno = EZS_ERR_SSL;
      return (0);
   }
   return (1);
}
   


/* Retrieve the session parameters - for later reuse */

char *ezs_get_session(EZS *E)
{
   char *session = NULL;
   BIO *sbio;
   BUF_MEM *sbio_mem;
   int r;

   if (!E) INVALID(NULL);

   if (!E->session) {
      E->ezs_errno = EZS_ERR_NO_CONNECTION;
      return (NULL);
   }

   sbio = BIO_new(BIO_s_mem());
   r = PEM_write_bio_SSL_SESSION(sbio,E->session);
   if (r) {
      BIO_get_mem_ptr(sbio, &sbio_mem);
      session = STRDUP(sbio_mem->data);
   }
   BIO_free_all(sbio);
   return (session);
}

/* Load previously saved session parameters */

int ezs_set_session(EZS *E, char *session)
{
   BIO *sbio;

   if (!E) INVALID(0);
   if (!session) INVALID_E(E,0);

   sbio = BIO_new_mem_buf(session, -1);
   E->session = PEM_read_bio_SSL_SESSION(sbio, NULL, NULL, NULL);
   BIO_free_all(sbio);
   if (!E->session) {
      E->ezs_errno = EZS_ERR_SSL;
      return (0);
   }
   return (1);
}


/* Client connect to service (host:port) */

int ezs_connect(EZS *E, char *service, char *cn)
{
   int sl = 1;
   int r;

   if (!E) INVALID(0);
   E->conn = BIO_new_connect(service);
   if (!E->conn) {
      E->ezs_errno = EZS_ERR_SSL;
      return (0);
   }

   if (BIO_do_connect(E->conn)<=0) {
      BIO_free_all(E->conn);
      E->conn = NULL;
      E->ezs_errno = EZS_ERR_SSL;
      return (0);
   }

   r = connect_bio(E, cn);
   return (r);
}

/* Establish an SSL session on a connected socket */

int ezs_connect_fd(EZS *E, int sock, char *cn)
{
   int sl = 1;
   int r;

   if (!E) INVALID (0);

 if (!E->connecting) {
   E->conn = BIO_new(BIO_s_fd());
   if (!E->conn) {
      E->ezs_errno = EZS_ERR_SSL;
      return (0);
   }
   BIO_set_fd(E->conn, sock, BIO_NOCLOSE);
 }

   r = connect_bio(E, cn);
   return (r);
}

/* Listen for connection */

int ezs_listen(EZS *E, char *port)
{

   if (!E) INVALID (0);
   E->conn = BIO_new_accept(port);
   if (!E->conn) {
      E->ezs_errno = EZS_ERR_SSL;
      return (0);
   }
   BIO_set_bind_mode(E->conn, BIO_BIND_REUSEADDR);

   if (BIO_do_accept(E->conn)<=0) {
      BIO_free_all(E->conn);
      E->conn = NULL;
      E->ezs_errno = EZS_ERR_SSL;
      return (0);
   }

   return (1);
}

/* Accept connection, returns new EZS struct  */

EZS *ezs_accept(EZS *A, char *cn)
{
   EZS *E;
   int sl = 1;

   if (!A) INVALID (0);

   E = (EZS*) MALLOC(sizeof(EZS));
   memset (E, '\0', sizeof(EZS));
   E->timeout = A->timeout;
   
   if (BIO_do_accept(A->conn) <=0) {
      E->ezs_errno = EZS_ERR_SSL;
      return (E);
   }
 
   BIO_set_bind_mode(E->conn, BIO_BIND_REUSEADDR);
   E->conn = BIO_pop(A->conn);

   accept_bio(E, cn);
   return (E);
}


/* Establish SSL on an already accepted socket  */

int ezs_accept_fd(EZS *E, int sock, char *cn)
{
   int sl = 1;
   int r;

   if (!E) INVALID (0);

   if (!E->connecting) {
     E->conn = BIO_new(BIO_s_fd());
     if (!E->conn) {
        E->ezs_errno = EZS_ERR_SSL;
        return (0);
     }
     BIO_set_fd(E->conn, sock, BIO_NOCLOSE);
   }
   r = accept_bio(E, cn);
   return (r);
}


/* Disconnect */

int ezs_disconnect(EZS *E)
{
   if (E) do_shutdown(E);
   return (1);
}



/* read and write
   return bytes written on success, else 0 */

int ezs_write(EZS *E, char *buf, int len)
{
   int n;
   int fd;
   fd_set rfds, wfds;
   struct timeval wait;
   int wblock, rblock;

   if (!E) INVALID (0);

   wait.tv_sec = E->timeout;
   wait.tv_usec = 0;
   FD_ZERO(&rfds);
   FD_ZERO(&wfds);
   FPRINTF(DEBUG_FP,"write sending %d bytes\n", len);

   if (!E->ssl) {
      E->ezs_errno = EZS_ERR_NO_CONNECTION;
      return (0);
   }

   /* Can't do write if read waiting */
   if (E->read_waiton_write) {
       FPRINTF(DEBUG_FP,"write postponed: read waiting %d\n", len);
       E->ezs_errno = EZS_ERR_WRITE_WOULDBLOCK;
       return (0);
   }
       
   E->write_waiton_read = 0;
   E->write_waiton_write = 0;

   fd = SSL_get_fd(E->ssl);

   for (;;) {

     rblock = 0;
     wblock = 0;

     n = SSL_write(E->ssl, buf, len);

     switch (SSL_get_error(E->ssl, n)) {
     
         case SSL_ERROR_NONE:   /* record completely written */
             return (n);     

         case SSL_ERROR_ZERO_RETURN:  /* eof */
             E->ezs_errno = EZS_ERR_WRITE_EOF;
             FPRINTF(DEBUG_FP, "write eof\n");
             return (0);

         case SSL_ERROR_WANT_READ:   /* renegotation in progress probably */
             FD_SET(fd, &rfds);
             rblock = 1;
             break;

         case SSL_ERROR_WANT_WRITE:  /* record not completely written */
             FD_SET(fd, &wfds);
             wblock = 1;
             break;
      
         case SSL_ERROR_SYSCALL:   
             if (n==0) {
                E->ezs_errno = EZS_ERR_WRITE_EOF;
                return (0);
             }
         case SSL_ERROR_SSL:   

         default:
             E->ezs_errno = EZS_ERR_SSL;
             do_shutdown(E);
             return (0);

     }

     /* not done yet */

     FPRINTF(DEBUG_FP,"write incomplete ... \n");

     if (E->timeout<=0) {
        E->ezs_errno = rblock? EZS_ERR_READ_WOULDBLOCK: EZS_ERR_WRITE_WOULDBLOCK;
        return (0);
     }

     n = select(fd+1, &rfds, &wfds, NULL, &wait);

     /* see if a read block is over */
     if (rblock) {
        if (FD_ISSET(fd, &rfds)) {
            continue;
        }
        E->write_waiton_read = 1;
        E->ezs_errno = EZS_ERR_READ_WOULDBLOCK;
        return (0);
     }

     /* see if a write block is over */
     if (wblock) {
        if (FD_ISSET(fd, &wfds)) {
            continue;
        }
        E->write_waiton_write = 1;
        E->ezs_errno = EZS_ERR_WRITE_WOULDBLOCK;
        return (0);
     }
   }
   
   E->ezs_errno = EZS_ERR_CANT_HAPPEN;;
   return (0);
}

/* semiblock read.  Allow 'timeout' time to complete
   returns number of bytes read, else 0 */

int ezs_read(EZS *E, char *buf, int len)
{
   int n;
   int fd;
   fd_set rfds, wfds;
   struct timeval wait;
   int wblock, rblock;

   if (!E) INVALID (0);

   wait.tv_sec = E->timeout;
   wait.tv_usec = 0;
   FD_ZERO(&rfds);
   FD_ZERO(&wfds);
   FPRINTF(DEBUG_FP,"read wants %d bytes\n", len);

   if (!E->ssl) {
      E->ezs_errno = EZS_ERR_NO_CONNECTION;
      return (0);
   }

   /* Can't do read if write waiting */
   if (E->write_waiton_read) {
       FPRINTF(DEBUG_FP,"read postponed: write waiting\n");
       E->ezs_errno = EZS_ERR_READ_WOULDBLOCK;
       return (0);
   }
   E->read_waiton_read = 0;
   E->read_waiton_write = 0;
       
   fd = SSL_get_fd(E->ssl);


   for (;;) {
     rblock = 0;
     wblock = 0;

     n = SSL_read(E->ssl, buf, len);
   
     switch (SSL_get_error(E->ssl, n)) {
     
         case SSL_ERROR_NONE:   /* record completely read */
             return (n);     

         case SSL_ERROR_ZERO_RETURN:  /* eof */
             E->ezs_errno = EZS_ERR_READ_EOF;
             FPRINTF(DEBUG_FP,"read eof\n");
             return (0);

         case SSL_ERROR_WANT_WRITE:   /* renegotation in progress probably */
             FD_SET(fd, &wfds);
             wblock = 1;
             break;

         case SSL_ERROR_WANT_READ:    /* record not completely received */
             FD_SET(fd, &rfds);
             rblock = 1;
             break;
      
         case SSL_ERROR_SYSCALL:   
             if (n==0) {
                E->ezs_errno = EZS_ERR_READ_EOF;
                return (0);
             }
         case SSL_ERROR_SSL:   

         default:
             E->ezs_errno = EZS_ERR_SSL;
             do_shutdown(E);
             return (0);

     }

     /* not done yet */

     FPRINTF(DEBUG_FP,"read incomplete ... \n");

     if (E->timeout<=0) {
        E->ezs_errno = rblock? EZS_ERR_READ_WOULDBLOCK: EZS_ERR_WRITE_WOULDBLOCK;
        return (0);
     }

     n = select(fd+1, &rfds, &wfds, NULL, &wait);

     /* see if a write block is over */
     if (wblock) {
        if (FD_ISSET(fd, &wfds)) {
            continue;
        }
        E->read_waiton_write = 1;
        E->ezs_errno = EZS_ERR_WRITE_WOULDBLOCK;
        return (0);
     }

     /* see if a read block is over */
     if (rblock) {
        if (SSL_pending(E->ssl) || FD_ISSET(fd, &rfds)) {
            continue;
        }
        E->read_waiton_read = 1;
        E->ezs_errno = EZS_ERR_READ_WOULDBLOCK;
        return (0);
     }
   }
   
   E->ezs_errno = EZS_ERR_CANT_HAPPEN;;
   return (0);
   
}

int ezs_bytes_for_read(EZS *E)
{
   if (!E) INVALID (0);
   return (SSL_pending(E->ssl));
}


/* ----  Cryption routines ------------- */

/* Display some data in hex. Note no line breaking.
   Note the arbitrary upper limit on length.
   The returned buffer must be freed.
   (this for debug) */

static char *pnbytes(unsigned char *byt, int n)
{
   int i;
   char *buf, *p;
   buf = (char *) MALLOC(n*2+1);
   p = buf;
   if (n>64) n = 64;
   for (i=0;i<n;i++) {
      sprintf(p,"%2.2x", *byt);
      byt++;
      p += 2;
   }
   *p = '\0';
   return (buf);
}

#define UC (unsigned char*)
void ezs_set_cipher(const EVP_CIPHER *(*cipher)())
{
   crypt_cipher = cipher;
}
void ezs_set_hash(const EVP_MD *(*hash)())
{
   crypt_hash = hash;
}

int ezs_crypt_init(EZS *E, char *keytext, int keylen, unsigned char **iv)
{
   int i, s;
   unsigned char key[EVP_MAX_KEY_LENGTH];
   unsigned char *iv0;
   char *prt_k, *prt_v;

   if (!E) INVALID (0);

   E->crypt_cipher = (EVP_CIPHER*)(*crypt_cipher)();
   E->crypt_hash = (EVP_MD*)(*crypt_hash)();
   iv0 = UC MALLOC(EVP_MAX_KEY_LENGTH);

   /* Don't know which way we're crypting, so setup both */
   s = EVP_BytesToKey(E->crypt_cipher, E->crypt_hash, NULL, UC keytext, keylen, 1, key, iv0);
   for (i=0;i<2;i++) {
     if (!E->ct[i]) E->ct[i]=(EVP_CIPHER_CTX *)MALLOC(sizeof(EVP_CIPHER_CTX));
     EVP_CipherInit(E->ct[i], E->crypt_cipher, key, (iv&&*iv)?*iv:iv0, i);
     if (ezs_debug) {
       prt_k = pnbytes(key, keylen);
       prt_v = pnbytes(iv0, keylen);
       fprintf(DEBUG_FP,">%d key(%d)=%s\n", i, keylen, prt_k);
       fprintf(DEBUG_FP,">%d  iv(%d)=%s\n", i, keylen, prt_v);
       FREE(prt_k);
       FREE(prt_v);
     }
   }

   /* return the generated iv */
   if (iv&&!*iv) *iv = iv0;
   else FREE(iv0);

   return (1);
}

/* crypt into a preallocated buffer */
int ezs_crypt(EZS *E, int mode, unsigned char *out, int *outlen, unsigned char *in, int inlen)
{
   int ol;
   int len;
   int s;
   
   if (!E) INVALID (0);

   if (E->reinit) EVP_CipherInit(E->ct[mode], NULL, NULL, NULL, mode);
   s = EVP_CipherUpdate(E->ct[mode], UC out, &ol, UC in, inlen);
   *outlen = ol;
   out += *outlen;
   FPRINTF(DEBUG_FP,"cipherupdate[%d], ol=%d\n", mode, ol);

   if (s) s = EVP_CipherFinal(E->ct[mode], UC out, &ol);
   *outlen += ol;
   
   len = *outlen;
   FPRINTF(DEBUG_FP,"cipherfinal[%d], ol=%d, outlen=%d\n", mode, ol, len);

   if (s) return (len);
   E->ezs_errno = EZS_ERR_SSL;
   return (0); 
}


/* Generate a MAC */
int ezs_hmac(unsigned char **hp, int *hlp, unsigned char *data, int dl, unsigned char *key, int kl)
{
   unsigned char *h = MALLOC(EVP_MAX_MD_SIZE);
   unsigned int hl = 0;

   EZS_INIT;

   memset (h, 0, EVP_MAX_MD_SIZE);
   HMAC((*crypt_hash)(), (void*) key, kl, data, dl, h, &hl);
   if (hp) *hp = h;
   if (hlp) *hlp = hl;
   return (1);
}

/* Base64 encode */
int ezs_data_to_base64(char **d64, int *d64l, void *data, int dl)
{
   BIO *b64, *bmem;
   BUF_MEM *bmem_mem;

   EZS_INIT;

   b64 = BIO_new(BIO_f_base64());
   bmem = BIO_new(BIO_s_mem());
   BIO_push(b64, bmem);
   
   BIO_write(b64, data, dl);
   BIO_flush(b64);
   BIO_get_mem_ptr(bmem, &bmem_mem);
   *d64 = STRDUP(bmem_mem->data);
   if (d64l) *d64l = bmem_mem->length;
   BIO_free_all(bmem);
   return (1);
}

/* Base64 decode */
int ezs_base64_to_data(void **data, int *dl, char *d64, int d64l)
{
   char *buf;
   int nb;
   BIO *b64, *bmem;

   EZS_INIT;

   b64 = BIO_new(BIO_f_base64());
   bmem = BIO_new_mem_buf(d64, d64l);
   BIO_push(b64, bmem);
   
   buf = MALLOC(d64l);
   nb = BIO_read(b64, buf, d64l);
   BIO_flush(b64);
   *data = buf;
   if (dl) *dl = nb;
   BIO_free_all(bmem);
   return (1);
}


