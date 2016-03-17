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
   Server demo version 2
     use non-blocking io
     use ezs_accept_fd

   Accept connection from client
     validate
     text from clients go to stdout
     text from stdin goes to clients

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


/* Clients */

typedef struct String_ {
  struct String_ *next;
  char *str;
} String;

typedef struct Client_ {
  struct Client_ *next;
  int state;
  EZS *E;
  int no;
  String *msg;      /* messages to client */
  THREAD_T reader;
  THREAD_T writer;
} Client;

Client *clients = NULL;
int clientno = 0;
/* make it simple with just the one lock */
MUTEX_T client_lock;

Client *new_client(EZS *E)
{
   Client *C = (Client*) malloc(sizeof(Client));
   MUTEX_LOCK(client_lock);
   C->next = clients;
   C->state = 1;
   C->E = E;
   C->no = clientno++;
   C->msg = NULL;
   clients = C;
   MUTEX_UNLOCK(client_lock);
   return (C);
}

void free_client(Client *C)
{
   Client *c, *p;
   MUTEX_LOCK(client_lock);
   for (p=NULL,c=clients; c!=C; p=c,c=c->next);
   if (c) {
      if (p) p->next = c->next;
      else clients = c->next;
   }
   MUTEX_UNLOCK(client_lock);
   free(C);
}

/* add a message to a client's output - caller has client lock */
void add_client_msg(Client *C, char *str)
{
   String *S, *s;

   if (!C->state) return;

   s = (String*) malloc(sizeof(String));
   s->str = strdup(str);
   s->next = NULL;
   S = C->msg;
   while (S&&S->next) S = S->next;
   if (S) S->next = s;
   else C->msg = s;
}

char *get_client_msg(Client *C)
{
   char *v;
   String *S;

   MUTEX_LOCK(client_lock);
   S = C->msg;
   if (S) C->msg = S->next;
   MUTEX_UNLOCK(client_lock);

   if (!S) return (NULL);
   v = S->str;
   free(S);
   return (v);
}

/* client reader thread */

THREAD_PROC client_reader(void *arg)
{
    Client *C = (Client*) arg;
    EZS *E = C->E;
    char rbuf[4096];
    int nb;
    int err;

    THREAD_DETACH;
    THREAD_OKCANCEL;
    fprintf(stderr, "client_thread\n");
    
    for (;;) {

       while (C->state && ((nb=ezs_read(E, rbuf, 4095))>0)) { 
           rbuf[nb] = '\0';
           printf("[%d] recv %d bytes: %s\n", C->no, nb, rbuf);
           if (!strncmp(rbuf,"#get ",5)) {
              printf("sending file '%s'\n", rbuf+5); 
              add_client_msg(C, rbuf);
           }
       }

       err = ezs_errno(E);
       if (!ezs_wouldblock(E)) {
          report_err(E, "read");
          break;
       }
       fprintf(stderr, "[%d] read would block: retry in 1 second\n", C->no);
       sleep(1);
    }

  
    /* THREAD_CANCEL(C->writer); */

    if (C->state==0) {
       ezs_disconnect(E);
       free_client(C);
    } else C->state = 0;

}

int client_send_file(Client *C, char *fname)
{
   EZS *E = C->E;
   FILE *fp;
   int p;
   char buf[4096];
   int nb;
   int done = 0;
   char *s;
   while (isspace(*fname)) fname++;
   if (s=strchr(fname, '\n')) *s = '\0';

   if (fp = fopen(fname,"r")) {
      fseek(fp, 0, SEEK_END);
      p = ftell(fp);
      fseek(fp, 0, SEEK_SET);
      printf("sending file %s (%d bytes) to %d\n", fname, p, C->no);
      sprintf(buf, "#file %s %d\n", fname, p);
      if (!ezs_write(E, buf, strlen(buf))) fatal_err(E, "sendfileinfo");
      while (!done) {
         nb = fread(buf, 1, 4096, fp);
         if (nb>0) {
            for (;;) {
               int rc = ezs_write(E, buf, nb);
               if (rc>0) break;
               if (ezs_wouldblock(E)) {
                  printf("write to %d blocked.  retry in 5 sec\n", C->no);
                  sleep(5);
               } else {
                  report_err(E, "write file");
                  done = 1;
                  break;
               }
            }
            printf("[%d] sent %d bytes\n", C->no, nb);
         } else {
            printf("sent\n");
            done = 1;
         }
      }
      fclose(fp);
   } else {
      add_client_msg(C, "no such file here");
      printf("file %s not found\n", fname);
   }
}

/* client writer thread */

THREAD_PROC client_writer(void *arg)
{
    Client *C = (Client*) arg;
    EZS *E = C->E;
    char *msg;
    int rc;
    int no = C->no;

    THREAD_DETACH;
    THREAD_OKCANCEL;
    C->state++;

    fprintf(stderr, "client_writer\n");

    /* should check for would blocj here as well */
    while (C->state) {
       msg = get_client_msg(C);
       if (msg) {
          if (!strncmp(msg, "#get ", 5)) {
             /* send file */
             client_send_file(C, msg+5);
          } else {
             rc = ezs_write(E, msg, strlen(msg));
             printf("[%d] sent %d bytes: %s\n", C->no, rc, msg);
          }
       } else sleep(1);
    }

    if (ezs_errno(E)) report_err(E, "write");

    if (C->state==0) {
       ezs_disconnect(E);
       free_client(C);
    } else C->state = 0;
}

/* thread to receive input from the terminal */

THREAD_PROC user_thread(void *arg)
{
   char sdata[4096];
   Client *C;

   THREAD_DETACH;
   fprintf(stderr, "user_thread\n");

   for (;;) {
      if (!fgets(sdata, 4095, stdin)) {
          perror("stdin");
          exit (1);
      }
      fprintf(stderr,"term: %s\n", sdata);
      
      MUTEX_LOCK(client_lock);
      for (C=clients; C; C=C->next) {
         fprintf(stderr,"add to %d: %s\n", C->no, sdata);
         add_client_msg(C, sdata);
      }
      MUTEX_UNLOCK(client_lock);
  } 
  exit (1);
}

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
        ezs_debug = 1;
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

  ezs_init("server2_demo");

  MUTEX_SETUP(client_lock);

  E = ezs_new();
  if (timeout>0) ezs_set_timeout(E, timeout);
  if (noblock) ezs_use_nonblocking_io(E);

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
  
    /* start a thread to receive user input */

    THREAD_CREATE(tid, user_thread, NULL);
 
/* Wait for connections */

  for (;;) {
  
     EZS *N;
     Client *C;
     int fd;
     char *from;
     int err;

     fd = accept(finet, SA &frominet, &f);
     if (fd < 0) {
        perror("accept: %m");
        break;
     }
     from = chkhost(&frominet);
     printf("Client accept from %s\n", from);
     lopt.l_onoff = 1;
     lopt.l_linger = 10;
     n = setsockopt(fd, SOL_SOCKET, SO_LINGER, &lopt, sizeof(lopt));
     if (n) perror("sockopt");

     N = ezs_new();
     if (timeout>0) ezs_set_timeout(N, timeout);
     if (noblock) ezs_use_nonblocking_io(N);

     for (;;) {
        fprintf(stderr, "doing ezs_accept_fd on %d\n", fd);
        if (ezs_accept_fd(N, fd, cn)) break;
        err = ezs_errno(N);
        if (!ezs_wouldblock(N)) fatal_err(N, "accept_fd");
        fprintf(stderr, "accept wouldbolck.  retry in 1 second\n");
        sleep(1);
     }
 
     /* start readers and writer for this client */

     C = new_client(N);

     THREAD_CREATE(C->reader, client_reader, C);
     THREAD_CREATE(C->writer, client_writer, C);

  } 
  exit (1);
}



