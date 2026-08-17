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

#ifndef UC_ASYNC_PROMISE_H
#define UC_ASYNC_PROMISE_H

#include "manager.h"

extern __hidden int
async_promise_destroy( async_manager_t *, async_todo_t *);

extern __hidden int
async_promise_do( async_manager_t *, async_todo_t *);

typedef struct async_promise
{
	async_todo_t header;
	async_manager_t *manager;
	struct uc_async_promise_resolver *resolver;
	union
	{
		uc_value_t *value;
		uc_exception_t *exception;
	} result;
	/* Contains the ucode function which caused the reject.
	To be used for the user feedback when no catch handler is found */
	uc_value_t *reject_caused_by;
	
    struct async_promise_method *stack;

} async_promise_t;

extern __hidden async_promise_t *
uc_promise_new( async_manager_t *manager );

extern __hidden void 
async_promise_init( async_manager_t *manager, uc_value_t *scope );

#endif //ndef UC_ASYNC_PROMISE_H
