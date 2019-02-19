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

/*
   Client demo version 1
     use blocking io
     use ezs_connect
     disable sslv3

   Connect to server
     validate
     text from server go to stdout
     text from stdin goes to server

   */
 


#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include "ezs.h"
#include "ezsthread.h"


/* local data */

char *prog;
int debug = 0;
char *ssl_session = NULL;

#ifdef WIN32
#include "openssl/applink.c"
#define sleep(s) Sleep(s*1000)
#endif

int usage()
{
   printf("usage: %s [-s server:port ] [-d] -ca ca_pem -c client_cert [-k client_key] [-t timeout]\n",prog);
   exit (1);
}

void report_err(EZS *E, char *msg)
{
   int e;
   char *t;
   e = ezs_geterror(E, &t);
   fprintf(stderr, ".. %s, ezs error %d %s\n", msg, e, t);
}

void fatal_err(EZS *E, char *msg)
{
   report_err(E, msg);
   exit (1);
}

/* thread to read from server */
THREAD_PROC server_thread(void *arg)
{
    EZS *E = (EZS*) arg;
    char rbuf[4096];
    int nb;
    FILE *sp;
    int err;

    /* THREAD_DETACH; */

    fprintf(stderr, "server_reader\n");
    ssl_session = ezs_get_session(E);
    if (ssl_session) {
       fprintf(stderr, "saving session\n");
       sp = fopen("session.pem", "w");
       fputs(ssl_session, sp);
       fclose(sp);
    }

    for (;;) {
       while ((nb=ezs_read(E, rbuf, 4095))>0) { 
           rbuf[nb] = '\0';
           printf("recv %d bytes: %s\n", nb, rbuf);
       }
       err = ezs_errno(E);
       if (!ezs_wouldblock(E)) {
          report_err(E, "read");
          break;
       }
       fprintf(stderr, "server read would block. retry in 1 second\n");
       sleep(1);
    }
}


int main(argc,argv)
int  argc;
char **argv;
{
 
   THREAD_T tid;
   char sdata [4096];
   size_t len;
   char *server = "";
   char *kfile = NULL;
   char *cfile = NULL;
   char *cafile = NULL;
   int timeout = 0;
   FILE *sp;
   char *cn = NULL;

   EZS *E;
    
   /* parse the args */

  prog = argv[0];
  while (--argc) {
     argv++;
     if (!strcmp(argv[0], "-s")) {
        if (--argc<0) usage();
        server = (++argv)[0];
     } else if (!strcmp(argv[0], "-c")) {
        if (--argc<0) usage();
        cfile = (++argv)[0];
     } else if (!strcmp(argv[0], "-k")) {
        if (--argc<0) usage();
        kfile = (++argv)[0];
     } else if (!strcmp(argv[0], "-ca")) {
        if (--argc<0) usage();
        cafile = (++argv)[0];
     } else if (!strcmp(argv[0], "-d")) {
        debug = 1;
        ezs_debug = 1;
     } else if (!strcmp(argv[0], "-t")) {
        if (--argc<0) usage();
        timeout = atoi((++argv)[0]);
     } else if (!strcmp(argv[0], "-v")) {
        fprintf(stderr, "client1 (ezs: incl=%s, lib=%s\n", EZS_VERSION_STRING, ezs_version());
        exit (1);
     } else usage();
  }

  if (!(server&&cfile&&cafile)) {
      fprintf(stderr,">> Need cert, ca, and server\n");
      usage();
  }
  if (!kfile) kfile = cfile;


  E = ezs_new();
  ezs_deny_v3(E);


  ezs_set_timeout(E, timeout);

  /* recover old session */
  if (sp=fopen("session.pem", "r")) {
     int r;
     len = fread(sdata, 1, 4096, sp);
     fclose(sp);
     fprintf(stderr, "using recovered session (%zd)\n", len);
     r = ezs_set_session(E, sdata);
     if (!r) report_err(NULL, "put session");
  }
  if (!ezs_add_ca(cafile)) fatal_err(NULL, "set ca");
  if (!ezs_add_cert(cfile, kfile, &cn)) fatal_err(NULL, "set cert");
  fprintf(stderr, "mycert cn=%s\n", cn);

  if (!ezs_connect(E, server, cn)) {
     fatal_err(E, "Connect");
  }

  printf("Connection established to '%s'.\n", server);
  
  /* start a tthread to receive server data */

   THREAD_CREATE(tid, server_thread, E);
  

/* Send user's input to the server.  */

  for (;;) {
     size_t nr;

     printf("> "); fflush(stdout);

     if (!fgets(sdata, 4095, stdin)) {
         perror("stdin");
         exit (1);
     }
     len = strlen(sdata);
     
     if (!E->ssl) {
         fprintf(stderr, "attempting reconnect\n");
         if (!ezs_connect(E, server, cn)) {
            fatal_err(E, "Reconnect");
         }
         fprintf(stderr, "Connection reestablished to '%s'\n", server);
         THREAD_CREATE(tid, server_thread, E);

     }
 
     if ((nr=ezs_write(E,sdata,(int)len))<0) {
        fatal_err(E, "write");
     }
     printf("send %zd bytes\n", len);
  } 

  exit (1);
}



