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
   Server demo version 3
     non-thread, simple version to test for memory leaks
     use ezs_accept_fd

   Accept connection from client
     validate
     loop:
        read one message
        write one message
     
     (wait for client disconnect)

   */
 
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <strings.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>


#include "ezs.h"
#include "ezsthread.h"

char *prog;
int debug = 0;

#ifdef WIN32
#include "openssl/applink.c"
#define sleep(s) Sleep(s*1000)
#endif


#define SA (struct sockaddr*)

int usage()
{
   printf("usage: %s -p port [-d] [-nb] -ca ca_pem -c server_cert [-k server_key] [-t timeout]\n", prog);
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


/* Because client reads and writes can block (in blocking mode)
   threads for each are created. Messages to clients are
   queued.  No such consideration is given to the console.
   */



int c_no = 0;




static char *chkhost(struct sockaddr_in *f)
{
  struct hostent *hp;
  extern char *inet_ntoa();
  char *from;
  hp = gethostbyaddr(&f->sin_addr, sizeof(struct in_addr), f->sin_family);
  if (hp)
    from = strdup(hp->h_name);
  else {
    from = strdup(inet_ntoa(f->sin_addr));
  }
  return (from);
}


main(argc,argv)
int  argc;
char **argv;
{
 
   THREAD_T tid;
   char sdata [4096];
   int len;
   char *port = NULL;
   char *kfile = NULL;
   char *cfile = NULL;
   char *cafile = NULL;
   char *cn = NULL;
   int port_num;
   int finet; 
   struct sockaddr_in sin, frominet;
   struct linger lopt;
   int optval = 1;
   int omask, lfd;
   socklen_t f;
   int n;
   int timeout = 0;
   int noblock = 0;

   EZS *E;

   FILE *of;
    
   /* parse the args */


  prog = argv[0];
  while (--argc) {
     argv++;
     if (!strcmp(argv[0], "-p")) {
        if (--argc<0) usage();
        port = (++argv)[0];
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
        ezs_debug = 0;
     } else if (!strcmp(argv[0], "-nb")) {
        noblock = 1;
     } else if (!strcmp(argv[0], "-t")) {
        if (--argc<0) usage();
        timeout = atoi((++argv)[0]);
     } else usage();
  }

  if (!(port&&cfile&&cafile)) {
      fprintf(stderr,">> Need cert, ca, and port\n");
      usage();
  }
  if (!kfile) kfile = cfile;
  if ((port_num=atoi(port))<=0) usage();

  /* ezs_init("server3_demo"); */
  ezs_init(NULL);

            CRYPTO_malloc_debug_init();
            CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);

            CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);


/**
  E = ezs_new();
  if (timeout>0) ezs_set_timeout(E, timeout);
  if (noblock) ezs_use_nonblocking_io(E);
 **/

  if (!ezs_add_ca(cafile)) fatal_err(NULL, "set ca");
  if (!ezs_add_cert(cfile, kfile, &cn))  fatal_err(NULL, "cert");
  fprintf(stderr, "mycert cn=%s\n", cn);


/* Open server listener socket */

    finet = socket(AF_INET, SOCK_STREAM, 0);
    if (finet<0) {
       perror("in-socket");
       exit(1);
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(port_num);
    if (bind(finet, SA &sin, sizeof(sin)) < 0) {
       perror("bind: %m");
       exit(1);
    }
    f = sizeof(sin);
    getsockname(finet, SA &sin, &f);

    if (setsockopt(finet, SOL_SOCKET, SO_KEEPALIVE, &optval, 4) < 0) {
       perror("setsockopt (SO_KEEPALIVE): %m");
       exit(1);
    }

    if (setsockopt(finet, SOL_SOCKET, SO_REUSEADDR, &optval, 4) < 0) {
       perror("setsockopt (SO_REUSEADDR): %m");
       exit(1);
    }

    lopt.l_onoff = 1;
    lopt.l_linger = 10;
    n = setsockopt(finet, SOL_SOCKET, SO_LINGER, &lopt, sizeof(lopt));
    if (n) perror("sockopt");

    listen(finet, 5);

    printf("Accepting connections, port '%s'.\n", port);
  
/* Wait for connections */

  for (c_no=0;c_no<10000;c_no++) {
  
     EZS *N;
     int fd;
     char *from;
     int err;
     int nl;

     fd = accept(finet, SA &frominet, &f);
     if (fd < 0) {
        perror("accept: %m");
        break;
     }
     from = chkhost(&frominet);
     if (debug) printf("Client accept from %s\n", from);
     free(from);
     lopt.l_onoff = 1;
     lopt.l_linger = 10;
     n = setsockopt(fd, SOL_SOCKET, SO_LINGER, &lopt, sizeof(lopt));
     if (n) perror("sockopt");

     N = ezs_new();
     if (timeout>0) ezs_set_timeout(N, timeout);
     if (noblock) ezs_use_nonblocking_io(N);

     for (;;) {
        if (debug>1) fprintf(stderr, "doing ezs_accept_fd on %d\n", fd);
        if (ezs_accept_fd(N, fd, cn)) break;
        err = ezs_errno(N);
        if (!ezs_wouldblock(N)) fatal_err(N, "accept_fd");
        if (debug) fprintf(stderr, "accept wouldbolck.  retry in 1 second\n");
        sleep(1);
     }
 
     for (nl=0;;nl++) {

        int nb;
        if ((nb=ezs_read(N, sdata, 4096))>0) {
          if (debug) fprintf(stderr, "recv %d bytes\n", nb);
           ezs_write(N,"Hello, client",12);
        } else {
           if (debug) fprintf(stderr, "recv err = %d\n", ezs_errno(N));
          break;
        }

     }
     if (debug>1) fprintf(stderr, "client gone after %d rw\n", nl);

     close(fd);
     ezs_disconnect(N);
     ezs_free(N);

  } 
  fprintf(stderr, "exit after %d connects\n", c_no);

  of = fopen("omem.log", "w");
  CRYPTO_mem_leaks_fp(of);
  fclose(of);
  exit (1);
}



