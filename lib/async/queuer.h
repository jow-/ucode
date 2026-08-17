/*
 * Copyright (C) 2025 Isaac de Wolff <idewolff@gmx.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
This file is part of the async plugin for ucode
*/
#ifndef ASYNC_QUEUER_H
#define ASYNC_QUEUER_H

#include <pthread.h>
#include "ucode/async.h"
#include "manager.h"

struct async_callback_queuer_chain;

typedef struct async_callback_queuer
{
	struct uc_async_callback_queuer header;

	// linked list of callbacks to be executed
	struct async_callback_queuer_chain *stack;
	int refcount;

	// Thread of the script
	pthread_t thread;
	// VM in which we live.
	async_manager_t *manager;
	// Stored sigmask
	sigset_t oldmask;
} async_callback_queuer_t;

extern __hidden void 
async_callback_queuer_init( async_manager_t *manager, uc_value_t *scope );


extern __hidden void
async_callback_queuer_free( async_manager_t *, async_callback_queuer_t * );

extern __hidden int
async_handle_queued_callbacks( async_manager_t *manager );

extern __hidden bool
async_any_queued_callbacks_waiting( async_manager_t *manager );

extern __hidden void
async_wakeup( const uc_async_callback_queuer_t *queuer );

extern __hidden void 
async_sleep( async_manager_t *manager, int64_t msec );


#endif // ndef ASYNC_QUEUER_H