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

#define FILE_MARKER "uapkic/stracktrace.c"

#include "stacktrace.h"

#include <string.h>
#include <stdlib.h>

#include "pthread-internal.h"

typedef struct StackTraceCtx_st {
    char *msg;
    unsigned long pid;
    ErrorCtx *head;
    ErrorCtx *tail;
} StackTraceCtx;

typedef struct ErrorsCtx_st {
    StackTraceCtx *stacktrace;
    struct ErrorsCtx_st *next;
} ErrorsCtx;

pthread_mutex_t errors_mutex = PTHREAD_MUTEX_INITIALIZER;
static ErrorsCtx *errors_list = NULL;

static StackTraceCtx *errors_get_stacktrace_by_pid(unsigned long pid)
{
    if (errors_list) {
        ErrorsCtx *err_curr = errors_list;
        while (err_curr != NULL) {
            if ((err_curr->stacktrace != NULL) && (err_curr->stacktrace->pid == pid)) {
                return err_curr->stacktrace;
            } else {
                err_curr = err_curr->next;
            }
        }
    }

    return NULL;
}

static ErrorCtx *error_ctx_create(const char *file, const size_t line, const int error_code)
{
    ErrorCtx *new_ctx = NULL;

    new_ctx = malloc(sizeof(ErrorCtx));
    if (new_ctx == NULL) {
        return NULL;
    }

    if (file) {
        size_t s_len = strlen(file) + 1;
        new_ctx->file = malloc(s_len);
        if (new_ctx->file == NULL) {
            free(new_ctx);
            return NULL;
        }
        memcpy(new_ctx->file, file, s_len);
    } else {
        new_ctx->file = NULL;
    }

    new_ctx->error_code = error_code;
    new_ctx->line = line;
    new_ctx->next = NULL;

    return new_ctx;
}

static void stacktrace_add_element(StackTraceCtx *errors_ctx, const char *file, const size_t line, const int error_code)
{
    ErrorCtx *new_ctx;

    new_ctx = error_ctx_create(file, line, error_code);
    if (new_ctx == NULL) {
        return;
    }

    if (errors_ctx->head == NULL) {
        errors_ctx->head = new_ctx;
    } else {
        errors_ctx->tail->next = new_ctx;
    }

    errors_ctx->tail = new_ctx;
}

static StackTraceCtx *errors_create_stacktrace(void)
{
    StackTraceCtx *stacktrace = malloc(sizeof(StackTraceCtx));

    if (stacktrace) {
        stacktrace->pid = pthread_id();
        stacktrace->head = NULL;
        stacktrace->tail = NULL;
        stacktrace->msg = NULL;

        ErrorsCtx *err = malloc(sizeof(ErrorsCtx));
        if (err) {
            err->stacktrace = stacktrace;
            err->next = errors_list;
        }

        errors_list = err;
    }

    return stacktrace;
}

void error_ctx_free(ErrorCtx *ctx)
{
    if (ctx) {
        ErrorCtx *error_curr = ctx;
        ErrorCtx *error_next;
        while (error_curr != NULL) {
            error_next = error_curr->next;
            free(error_curr->file);
            free(error_curr);
            error_curr = error_next;
        }
    }
}

static ErrorCtx *error_copy_with_alloc(ErrorCtx *ctx)
{
    ErrorCtx *out = NULL;

    if (ctx == NULL) {
        return NULL;
    }

    out = error_ctx_create(ctx->file, ctx->line, ctx->error_code);

    if (out) {
        ErrorCtx *error_next = ctx->next;
        ErrorCtx *out_curr = out;

        while (error_next) {
            out_curr->next = error_ctx_create(error_next->file, error_next->line, error_next->error_code);
            error_next = error_next->next;
            out_curr = out_curr->next;
        }
    }

    return out;
}

void stacktrace_create(const char *file, const size_t line, const int error_code, const char *msg)
{
    pthread_mutex_lock(&errors_mutex);

    unsigned long pid = pthread_id();
    StackTraceCtx *stacktrace = errors_get_stacktrace_by_pid(pid);

    if (stacktrace != NULL) {
        error_ctx_free(stacktrace->head);
        stacktrace->head = NULL;
        stacktrace->tail = NULL;
        stacktrace->msg = NULL;
    } else {
        stacktrace = errors_create_stacktrace();
    }

    stacktrace_add_element(stacktrace, file, line, error_code);

    /* Copy msg. */
    free(stacktrace->msg);
    if (msg != NULL) {
        size_t s_len = strlen(msg) + 1;
        stacktrace->msg = malloc(s_len);
        if (stacktrace->msg != NULL) {
            memcpy(stacktrace->msg, msg, s_len);
        }
    } else {
        stacktrace->msg = NULL;
    }

    pthread_mutex_unlock(&errors_mutex);
}

void stacktrace_add(const char *file, const size_t line, const int error_code)
{
    pthread_mutex_lock(&errors_mutex);

    unsigned long pid = pthread_id();
    StackTraceCtx *stacktrace = errors_get_stacktrace_by_pid(pid);

    if (stacktrace == NULL) {
        stacktrace = errors_create_stacktrace();
    }

    stacktrace_add_element(stacktrace, file, line, error_code);

    pthread_mutex_unlock(&errors_mutex);
}

const ErrorCtx *stacktrace_get_last(void)
{
    unsigned long tid = pthread_id();
    ErrorCtx *out;

    pthread_mutex_lock(&errors_mutex);

    StackTraceCtx *stracktrace = errors_get_stacktrace_by_pid(tid);
    out = (stracktrace != NULL) ? stracktrace->head : NULL;

    pthread_mutex_unlock(&errors_mutex);

    return out;
}

static void stacktrace_free(StackTraceCtx *stacktrace)
{
    if (stacktrace) {
        error_ctx_free(stacktrace->head);
        free(stacktrace->msg);
        free(stacktrace);
    }
}

static void errors_free(ErrorsCtx *ctx)
{
    if (ctx) {
        stacktrace_free(ctx->stacktrace);
        free(ctx);
    }
}

void stacktrace_free_current(void)
{
    unsigned long pid = pthread_id();

    pthread_mutex_lock(&errors_mutex);

    if (errors_list) {
        if (errors_list->stacktrace != NULL && errors_list->stacktrace->pid == pid) {
            if (errors_list->next == NULL) {
                errors_free(errors_list);
                errors_list = NULL;
            } else {
                ErrorsCtx *errors_list_ptr = errors_list;
                errors_list = errors_list->next;
                errors_free(errors_list_ptr);
            }
        } else {
            ErrorsCtx *errors_curr = errors_list;
            ErrorsCtx *errors_next;

            while (errors_curr != NULL) {
                errors_next = errors_curr->next;
                if (errors_next != NULL && errors_next->stacktrace != NULL
                        && errors_next->stacktrace->pid == pid) {
                    errors_curr->next = (errors_next->next != NULL) ? errors_next->next : NULL;
                    errors_free(errors_next);
                    break;
                }
                errors_curr = errors_next;
            }
        }
    }

    pthread_mutex_unlock(&errors_mutex);
}

ErrorCtx *stacktrace_get_last_with_alloc(void)
{
    ErrorCtx *error_ctx_new = NULL;

    pthread_mutex_lock(&errors_mutex);

    StackTraceCtx *stracktrace = errors_get_stacktrace_by_pid(pthread_id());
    if (stracktrace != NULL) {
        error_ctx_new = error_copy_with_alloc(stracktrace->head);
    }

    pthread_mutex_unlock(&errors_mutex);

    return error_ctx_new;
}

void stacktrace_finalize(void)
{
    pthread_mutex_lock(&errors_mutex);

    if (errors_list) {
        ErrorsCtx *errors_curr = errors_list;
        ErrorsCtx *errors_next;
        while (errors_curr != NULL) {
            errors_next = errors_curr->next;
            errors_free(errors_curr);
            errors_curr = errors_next;
        }
        errors_list = NULL;
    }

    pthread_mutex_unlock(&errors_mutex);
}
