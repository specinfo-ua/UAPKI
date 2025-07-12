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

#define FILE_MARKER "uapkic/pthread-impl.c"

#include "pthread-internal.h"
#include <string.h>

#ifdef _WIN32
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*startup)(void *), void *params)
{
    DWORD threadid;
    HANDLE h;

    if (attr) {
        h = CreateThread(attr->threadAttributes,
                attr->stackSize,
                (DWORD (WINAPI *)(LPVOID))startup,
                params,
                attr->creationFlags,
                &threadid);
    } else {
        h = CreateThread(NULL,
                0,
                (DWORD (WINAPI *)(LPVOID))startup,
                params,
                0,
                &threadid);
    }

    thread->tid = threadid;

    if (!h) {
        return -1;
    }

    if (attr && (attr->detachState == PTHREAD_CREATE_DETACHED)) {
        CloseHandle(h);
    } else {
        thread->handle = h;
    }

    return 0;
}

void pthread_exit(void *value_ptr)
{
    if (value_ptr) {
        ExitThread(*(DWORD *)value_ptr);
    } else {
        ExitThread(0);
    }
}

int pthread_join(pthread_t thread, void **value_ptr)
{
    DWORD ret;

    if (!thread.handle) {
        return -1;
    }

    ret = WaitForSingleObject(thread.handle, INFINITE);
    if (ret == WAIT_FAILED) {
        return -1;
    } else if ((ret == WAIT_ABANDONED) || (ret == WAIT_OBJECT_0)) {
        if (value_ptr) {
            GetExitCodeThread(thread.handle, (LPDWORD)value_ptr);
        }
    }

    return 0;
}

int pthread_detach(pthread_t thread)
{
    if (!thread.handle) {
        return -1;
    }

    CloseHandle(thread.handle);
    thread.handle = 0;

    return 0;
}

int pthread_cancel(pthread_t thread)
{
    (void)thread;
    return 0;
}

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr)
{
    (void)attr;

    if (mutex) {
        if (mutex->mutex) {
            return EBUSY;
        }

        mutex->mutex = CreateMutexW(NULL, FALSE, NULL);
        mutex->lockedOrReferenced = 0;
    }

    return 0;
}

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
    DWORD ret;

    if (!mutex) {
        return EINVAL;
    }

    if (!mutex->mutex) {
        pthread_mutex_init(mutex, NULL);
    }

    if (!mutex->mutex) {
        return EINVAL;
    }

    ret = WaitForSingleObject(mutex->mutex, INFINITE);

    if (ret != WAIT_FAILED) {
        mutex->lockedOrReferenced = 1;
        return 0;
    } else {
        return EINVAL;
    }
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    DWORD ret;

    if (!mutex) {
        return EINVAL;
    }

    ret = ReleaseMutex(mutex->mutex);

    if (ret != 0) {
        mutex->lockedOrReferenced = 0;
        return 0;
    } else {
        return EPERM;
    }
}

int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
    if (!mutex) {
        return EINVAL;
    }

    if (mutex->lockedOrReferenced) {
        return EBUSY;
    }

    CloseHandle(mutex->mutex);
    mutex->mutex = NULL;

    return 0;
}

int pthread_attr_init(pthread_attr_t* attr)
{
    memset(attr, 0, sizeof(pthread_attr_t));
    return 0;
}

int pthread_attr_destroy(pthread_attr_t* attr)
{
    memset(attr, 0, sizeof(pthread_attr_t));
    return 0;
}
#endif

unsigned long pthread_id(void)
{
#ifdef _WIN32
    return GetCurrentThreadId();
#else
    return (unsigned long)pthread_self();
#endif
}
