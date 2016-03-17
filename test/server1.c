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
   Server demo version 1
     use blocking io
     use ezs_accept

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
#include <signal.h>

#include "ezs.h"
#include "ezsthread.h"

char *prog;
int debug = 1;  /* verbose */
int count_clients = 0;

int tot_clients = 0;
int tot_rt = 0;
int tot_wt = 0;
int tot_pipe = 0;

/** unused: ezs lib sets sigpipe to ignore 
void catch_pipe(int i)
{
   signal(SIGPIPE, catch_pipe);
   tot_pipe++;
}
 **/

static void show_client_count() 
{
   printf("\r%7d %4d %4d %3d", tot_clients, tot_rt, tot_wt, tot_pipe);
   fflush(stdout);
}

#ifdef WIN32
#include "openssl/applink.c"
#define sleep(s) Sleep(s*1000)
#endif

int usage()
{
   printf("usage: %s -p port [-q] [-d] -ca ca_pem [-crl crl_pem] -c server_cert [-k server_key] [-t timeout]\n", prog);
   exit (1);
}

void report_err(EZS *E, char *msg)
{
   int e;
   char *t;
   e = ezs_geterror(E, &t);
   if (debug||(e!=10)) fprintf(stderr, ".. %s, ezs error %d %s\n", msg, e, t);
   if (t) free(t);
}

void fatal_err(EZS *E, char *msg)
{
   report_err(E, msg);
   exit (1);
}


/* Because client reads and writes can block
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

    THREAD_DETACH;
    THREAD_OKCANCEL;
    C->state++;
    tot_rt++;
    if (debug>1) fprintf(stderr, "new client_thread\n");
    
    while (C->state && ((nb=ezs_read(E, rbuf, 4095))>0)) { 
        rbuf[nb] = '\0';
        if (debug) printf("[%d] recv %d bytes: %s\n", C->no, nb, rbuf);
        if (!strncmp(rbuf, "exit", 4)) exit (0);
    }

    if ( nb<=0) report_err(E, "read");
  
    /* THREAD_CANCEL(C->writer); */

    if (C->state==0) {
       ezs_disconnect(E);
       free_client(C);
    } else C->state = 0;
    
    tot_rt--;

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
    tot_wt++;

    if (debug>1) fprintf(stderr, "new client_writer\n");

    while (C->state) {
       msg = get_client_msg(C);
       if (msg) {
          rc = ezs_write(E, msg, strlen(msg));
          if (debug) printf("[%d] sent %d bytes: %s\n", C->no, rc, msg);
          if (rc<=0) {
              report_err(E, "write");
              if (ezs_geterror(E, NULL)==EZS_ERR_NO_CONNECTION) break;
          }
       } else sleep(1);
    }

    if (C->state==0) {
       ezs_disconnect(E);
       free_client(C);
    } else C->state = 0;

    tot_wt--;
}

/* thread to receive input from the terminal */

THREAD_PROC user_thread(void *arg)
{
   char sdata[4096];
   Client *C;

   THREAD_DETACH;
   if (debug>1) fprintf(stderr, "new user_thread\n");

   for (;;) {
      if (!fgets(sdata, 4095, stdin)) {
          perror("stdin");
          exit (1);
      }
      if (debug>1) fprintf(stderr,"term: %s\n", sdata);
      
      if (!strncmp(sdata,"crl ",4)) {
         char *p, *e;
         for (p=sdata+4; *p==' '; p++);
         if (e=strchr(p, '\n')) *e = '\0';
         ezs_add_crl(p);
         
      } else if (!strcmp(sdata,"verbose")) {
         debug = 1;

      } else if (!strcmp(sdata,"debug")) {
         debug = 2;

      } else if (!strcmp(sdata,"quiet")) {
         debug = 0;

      } else if (!strcmp(sdata,"ncc")) {
         count_clients = 1;

      } else if (!strcmp(sdata,"cc")) {
         count_clients = 1;
         show_client_count();

      } else {  /* send message to clients */

         MUTEX_LOCK(client_lock);
         for (C=clients; C; C=C->next) {
            if (debug>1) fprintf(stderr,"add to %d: %s\n", C->no, sdata);
            add_client_msg(C, sdata);
         }
         MUTEX_UNLOCK(client_lock);
      }
      if (count_clients) show_client_count();
  } 
  exit (1);
}

main(argc,argv)
int  argc;
char **argv;
{
 
   pthread_t tid;
   char sdata [4096];
   int len;
   char *port = NULL;
   char *kfile = NULL;
   char *cfile = NULL;
   char *cafile = NULL;
   char *crlfile = NULL;
   char *cn = NULL;
   int timeout = 0;

   EZS *E;

   int term_input = 1;
    
   /* parse the args */

  /* signal(SIGPIPE, catch_pipe); */

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
     } else if (!strcmp(argv[0], "-crl")) {
        if (--argc<0) usage();
        crlfile = (++argv)[0];
     } else if (!strcmp(argv[0], "-q")) {
        debug = 0;
        ezs_debug = 0;
     } else if (!strcmp(argv[0], "-d")) {
        debug = 2;
        ezs_debug = 1;
     } else if (!strcmp(argv[0], "-nt")) {
        term_input = 0;
     } else if (!strcmp(argv[0], "-t")) {
        if (--argc<0) usage();
        timeout = atoi((++argv)[0]);
     } else if (!strcmp(argv[0], "-cc")) {
        count_clients = 1;
     } else usage();
  }

  if (!(port&&cfile&&cafile)) {
      fprintf(stderr,">> Need cert, ca, and port\n");
      usage();
  }
  if (!kfile) kfile = cfile;

  ezs_init("server1_demo");

  MUTEX_SETUP(client_lock);

  E = ezs_new();
  if (timeout>0) ezs_set_timeout(E, timeout);

  if (!ezs_add_ca(cafile)) fatal_err(NULL, "ca");
  if (crlfile && !ezs_add_crl(crlfile)) fatal_err(NULL, "crl");
  if (!ezs_add_cert(cfile, kfile, &cn)) fatal_err(NULL, "crt");
  if (debug) fprintf(stderr, "mycert cn=%s\n", cn);

  if (!ezs_listen(E, port)) fatal_err(NULL, "listen");

  printf("Accepting connections, port '%s'.\n", port);
  
  /* start a thread to receive user input */

  if (term_input) THREAD_CREATE(tid, user_thread, (void *)NULL);
 
/* Wait for connections */

  for (;;) {
  
     EZS *N;
     Client *C;

     N = ezs_accept(E, cn);

     if (!N) fatal_err(NULL, "accept");

     /* start readers and writer for this client */

     C = new_client(N);

     THREAD_CREATE(C->reader, client_reader, (void *)C);
     THREAD_CREATE(C->writer, client_writer, (void *)C);

     tot_clients++;
     if (count_clients) show_client_count();

  } 
  printf("Exiting\n");
  exit (1);
}



