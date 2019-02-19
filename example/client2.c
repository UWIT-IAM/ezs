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
   Client demo version 2
     use blocking io
     use ezs_connect_fd

   Connect to server
     validate
     text from server go to stdout
     text from stdin goes to server

   */
 
 
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <strings.h>
#include <sys/types.h>

#include <netdb.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef _AIX
#include <sys/select.h>
#endif

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
   printf("usage: %s [-s server:port ] [-d] -ca ca_pem -c client_cert [-k client_key] [-t timeout]\n", prog);
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

int receive_file(EZS *E, char *info) 
{
   char *s;
   int siz;
   int nr = 0;
   int nb;
   char buf[4096];
   FILE *fp;
   while (isspace(*info)) info++;
   for (s=info; *s && !isspace(*s); s++);
   *s++ = '\0';
   while (isspace(*s)) s++;
   siz = atoi(s);
   printf("receiving file '%s' (%d bytes)\n", info, siz);
   if (fp=fopen(info, "w")) {
      while (nr<siz) {
         int n = siz-nr;
         if (n>4096) n = 4096;
         nb = ezs_read(E, buf, n);
         if (nb>0) {
            printf("recv %d bytes\n", nb);
            fwrite(buf, 1, nb, fp);
            nr += nb;
         } else {
            if (ezs_wouldblock(E)) {
               printf("read blocked.  retry in 5 sec\n");
               sleep(5);
            } else fatal_err(E, "readfile");
         }
      }
   } else {
     perror(info);
     exit (1);
   }
   fclose(fp);
   printf("readfile done\n");

}


/* server reader */
THREAD_PROC server_thread(void *arg)
{
    EZS *E = (EZS*) arg;
    char rbuf[4096];
    int nb;
    FILE *sp;

    THREAD_DETACH;

    fprintf(stderr, "server_reader\n");
    ssl_session = ezs_get_session(E);
    if (ssl_session) {
       fprintf(stderr, "saving session\n");
       sp = fopen("session.pem", "w");
       fputs(ssl_session, sp);
       fclose(sp);
    }

    while ((nb=ezs_read(E, rbuf, 4095))>0) { 
        rbuf[nb] = '\0';
        printf("recv %d bytes: %s\n", nb, rbuf);
        if (!strncmp(rbuf, "#file ", 6)) {
           if (!receive_file(E, rbuf+6)) break;
        }
    }
    report_err(E, "read");

}


int main(argc,argv)
int  argc;
char **argv;
{
 
   THREAD_T tid;
   char sdata [4096];
   int len;
   char *server = NULL;
   char *kfile = NULL;
   char *cfile = NULL;
   char *cafile = NULL;
   int timeout = 0;
   FILE *sp;
   char *cn = NULL;
   struct sockaddr_in sa_in;
   register struct hostent *host = 0;
   int port_num;
   char *s;
   char    hnamebuf[32], *hostname;
   int     connected;
   int     sock;

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
  if (!(s=strchr(server,':'))) usage();
  *s++ = '\0';
  port_num = atoi(s);
  if (port_num<=0) usage();

  E = ezs_new();
  ezs_set_timeout(E, timeout);

  /* recover old session */
  if (sp=fopen("session.pem", "r")) {
     int r;
     r = fread(sdata, 1, 4096, sp);
     fclose(sp);
     fprintf(stderr, "using recovered session (%d)\n", r);
     r = ezs_set_session(E, sdata);
     if (!r) report_err(NULL, "put session");
  }
  if (!ezs_add_ca(cafile)) fatal_err(NULL, "set ca");
  if (!ezs_add_cert(cfile, kfile, &cn)) fatal_err(NULL, "set cert");
  fprintf(stderr, "mycert cn=%s\n", cn);

   /*  Open a connection to a server. */

   sa_in.sin_port = htons(port_num);
   sa_in.sin_addr.s_addr = inet_addr(server);
   if (sa_in.sin_addr.s_addr != -1) {
      sa_in.sin_family = AF_INET;
      (void) strcpy(hnamebuf, server);
      hostname = hnamebuf;
   } else {
      host = gethostbyname(server);
      if (host) {
         sa_in.sin_family = host->h_addrtype;
         bcopy(host->h_addr, (caddr_t)&sa_in.sin_addr, host->h_length);
         hostname = host->h_name;
      } else {
         fprintf(stderr,"%s: unknown host\n", server);
         exit(1);
      }
   }

   printf("Trying %s...\n",inet_ntoa(sa_in.sin_addr));
   sock = socket(AF_INET, SOCK_STREAM, 0);
   if (sock < 0) {
     perror("inet socket");
     exit(1);
   }
   if (connect(sock, (struct sockaddr *)&sa_in, sizeof (sa_in)) < 0) {
      perror("connect");
      exit(1);
   }

  if (!ezs_connect_fd(E, sock, cn)) {
     fatal_err(E, "Connect");
  }

  printf("Connection established to '%s'.\n", server);
  
  /* start a tthread to receive server data */

  THREAD_CREATE(tid, server_thread, E);
 
/* Send user's input to the server.  */

  for (;;) {
     int nr;

     printf("> "); fflush(stdout);

     if (!fgets(sdata, 4095, stdin)) {
         perror("stdin");
         exit (1);
     }
     len = strlen(sdata);
     
     if (!E->ssl) {
         fprintf(stderr, "attempting reconnect\n");
         if (!ezs_connect(E, server, cn)) {
           fatal_err(E, "RecConnect");
         }
         fprintf(stderr, "Connection reestablished to '%s'\n", server);
         THREAD_CREATE(tid, server_thread, E);
     }
 
     if ((nr=ezs_write(E,sdata,len))<0) {
         fatal_err(E, "write");
         exit (1);
     }
     printf("send %d bytes\n", len);
  } 
  exit (1);
}



