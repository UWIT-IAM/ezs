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
     memory leak test client - repeated connect and disconnect
     use blocking io
     use ezs_connect

   Connect to server
     validate
     send something
     disconnect
     repeat

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


main(argc,argv)
int  argc;
char **argv;
{
 
   THREAD_T tid;
   char sdata [4096];
   size_t len;
   char *server = "lost.cac.washington.edu:2000";
   char *kfile = NULL;
   char *cfile = "c:\\src\\lost.ck";
   char *cafile = "c:\\src\\uwca.crt";
   int timeout = 0;
   FILE *sp;
   char *cn = NULL;
   int connect_count;

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
     } else usage();
  }

  if (!(server&&cfile&&cafile)) {
      fprintf(stderr,">> Need cert, ca, and server\n");
      usage();
  }
  if (!kfile) kfile = cfile;

     E = ezs_new();
     ezs_set_timeout(E, timeout);

#ifdef USE_SESSIONS
  /* recover old session */
  if (sp=fopen("session.pem", "r")) {
     int r;
     len = fread(sdata, 1, 4096, sp);
     fclose(sp);
     fprintf(stderr, "using recovered session (%d)\n", len);
     r = ezs_set_session(E, sdata);
     if (!r) report_err(NULL, "put session");
  }
#endif
  if (!ezs_add_ca(cafile)) fatal_err(NULL, "set ca");
  if (!ezs_add_cert(cfile, kfile, &cn)) fatal_err(NULL, "set cert");
  fprintf(stderr, "mycert cn=%s\n", cn);

  for (connect_count=0;;connect_count++) {
     int nr;
     

     if (!ezs_connect(E, server, cn)) {
        fatal_err(E, "Connect");
     }
     if (debug>0) printf("Connection established to '%s'.\n", server);

      sprintf(sdata, "trial connection %d", connect_count);
      len = strlen(sdata);
   
     
     if ((nr=ezs_write(E,sdata,(int)len))<0) {
        fatal_err(E, "write");
     }
     if (debug>0) printf("send %zd bytes\n", len);
     ezs_disconnect(E);

     if (debug) sleep(1);
     else if (connect_count && ((connect_count/100)*100 == connect_count)) fprintf(stderr, "%d\r", connect_count);
  } 

  fprintf(stderr, "Disconnect after %d connects\n", connect_count);
  exit (1);
}



