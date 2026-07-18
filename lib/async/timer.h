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

#ifndef UC_ASYNC_TIMER_H
#define UC_ASYNC_TIMER_H

#include "manager.h"
#include "callback.h"

extern __hidden int64_t
async_timer_current_time();

typedef struct async_timer
{
	async_todo_t header;
	int64_t due;
	uint32_t periodic;
	struct async_callback callback;
} async_timer_t;

// Safety. Let the compiler error out when the wrong type is casted.
static inline struct async_timer *
async_timer_cast(async_todo_t *p)
{
	DEBUG_ASSERT(p->todo_type & todoTimer);
	return (struct async_timer *)p;
}

extern __hidden void 
async_timer_destroy( async_manager_t *, async_todo_t * );

extern __hidden int 
async_timer_do( async_manager_t *, async_todo_t * );

extern __hidden struct async_timer *
async_timer_c_int_user_flags_new( async_manager_t *manager, int (*func)(uc_vm_t *, void *, int), void *user);

extern __hidden void 
async_timer_init( async_manager_t *manager, uc_value_t *scope );

#endif //ndef UC_ASYNC_TIMER_H
