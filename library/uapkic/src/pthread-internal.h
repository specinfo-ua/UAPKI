/*
 * Copyright 2021 The UAPKI Project Authors.
 * Copyright 2016 PrivatBank IT <acsk@privatbank.ua>
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are 
 * met:
 * 
 * 1. Redistributions of source code must retain the above copyright 
 * notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright 
 * notice, this list of conditions and the following disclaimer in the 
 * documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS 
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED 
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A 
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED 
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PTHREAD_INTERNAL_H_
#define PTHREAD_INTERNAL_H_

#ifdef _WIN32
#include <windows.h>
#include <errno.h>

#define PTHREAD_CANCEL_ASYNCHRONOUS 1
#define PTHREAD_CANCEL_ENABLE       2
#define PTHREAD_CANCEL_DEFERRED     3
#define PTHREAD_CANCEL_DISABLE      4
#define PTHREAD_CANCELED            5
#define PTHREAD_COND_INITIALIZER    {0}
#define PTHREAD_CREATE_DETACHED     6
#define PTHREAD_CREATE_JOINABLE     7
#define PTHREAD_EXPLICIT_SCHED      8
#define PTHREAD_INHERIT_SCHED       9
#define PTHREAD_MUTEX_DEFAULT       {0}
#define PTHREAD_MUTEX_ERRORCHECK    {0}
#define PTHREAD_MUTEX_NORMAL        {0}
#define PTHREAD_MUTEX_INITIALIZER   {0}
#define PTHREAD_MUTEX_RECURSIVE     {0}
#define PTHREAD_ONCE_INIT           10
#define PTHREAD_PRIO_INHERIT        11
#define PTHREAD_PRIO_NONE           12
#define PTHREAD_PRIO_PROTECT        13
#define PTHREAD_PROCESS_SHARED      14
#define PTHREAD_PROCESS_PRIVATE     15
#define PTHREAD_RWLOCK_INITIALIZER  {0}
#define PTHREAD_SCOPE_PROCESS       16
#define PTHREAD_SCOPE_SYSTEM        17

typedef struct {
    HANDLE handle;
    unsigned int tid;
} pthread_t;

typedef struct {
    LPSECURITY_ATTRIBUTES threadAttributes;
    SIZE_T stackSize;
    void *stackAddr;
    DWORD creationFlags;
    int detachState;
    int contentionScope;
    int policy; /*supported values: SCHED_FIFO, SCHED_RR, and SCHED_OTHER*/
    int inheritSched;
    int detach;
} pthread_attr_t;

typedef struct {
    HANDLE mutex;
    int lockedOrReferenced;
} pthread_mutex_t;

typedef struct {
    int protocol;
    int pShared;
    int prioCeiling;
    int type;
} pthread_mutexattr_t;

int pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int pthread_cancel(pthread_t);
int pthread_detach(pthread_t);
void pthread_exit(void *);
int pthread_join(pthread_t, void **);
int pthread_mutex_destroy(pthread_mutex_t *);
int pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
int pthread_mutex_lock(pthread_mutex_t *);
int pthread_mutex_unlock(pthread_mutex_t *);
int pthread_attr_init(pthread_attr_t* attr);
int pthread_attr_destroy(pthread_attr_t* attr);
#else

#include <pthread.h>
#include <unistd.h>
#endif /* _WIN32 */

unsigned long pthread_id(void);

#endif /* PTHREAD_INTERNAL_H_ */
