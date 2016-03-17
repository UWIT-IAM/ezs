#ifndef EZSTHREAD_H
#define EZSTHREAD_H

#if defined(WIN32)
  #include <windows.h>
  #include <process.h>
#else
  #include <unistd.h>
  #include <pthread.h>
#endif

#include <openssl/ssl.h>

int ezs_THREAD_setup(void);
int ezs_THREAD_leanup(void);

#if defined(WIN32)

/* don't know about some of these */
    #define THREAD_T HANDLE
    #define THREAD_PROC void
    #define THREAD_CREATE(id, proc, arg) id=(HANDLE)_beginthread(proc,0,arg)
    #define THREAD_ID GetCurrentThreadId( )
    #define THREAD_DETACH 
    #define THREAD_CANCEL(t)  TerminateThread((HANDLE*)t, 0)
    #define THREAD_OKCANCEL 

    #define MUTEX_T HANDLE
    #define MUTEX_SETUP(x) (x) = CreateMutex(NULL, FALSE, NULL)
    #define MUTEX_CLEANUP(x) CloseHandle(x)
    #define MUTEX_LOCK(x) WaitForSingleObject((x), INFINITE)
    #define MUTEX_UNLOCK(x) ReleaseMutex(x)

#elif defined(_POSIX_THREADS)

    #define THREAD_T pthread_t
    #define THREAD_PROC void*
    #define THREAD_CREATE(id, proc, arg) pthread_create(&id, NULL, proc, (void*)arg)
    #define THREAD_ID pthread_self( )
    #define THREAD_DETACH pthread_detach(pthread_self());
    #define THREAD_CANCEL(t) pthread_cancel(t)
    #define THREAD_OKCANCEL pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)

    #define MUTEX_T pthread_mutex_t
    #define MUTEX_SETUP(x) pthread_mutex_init(&(x), NULL)
    #define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
    #define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
    #define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))

#else
    #bomb No thread definitions!
#endif

#endif /* EZSTHREAD_H */
