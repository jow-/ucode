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

#ifndef UC_ASYNC_MANAGER_H
#define UC_ASYNC_MANAGER_H

#include "ucode/platform.h"
#include "ucode/async.h"

// #define DEBUG_PRINT
#define ASYNC_HAS_UPTIME
#define ASYNC_HAS_ALIENS

#ifdef __APPLE__
// For now. Aliens needs Linux futex, which isn't available on MacOS.
#	undef ASYNC_HAS_ALIENS
#endif

#ifdef DEBUG_PRINT
#   define DEBUG_PRINTF(...) printf(__VA_ARGS__)
#   define ASYNC_HAS_UPTIME
#else
#   define DEBUG_PRINTF(...)
#endif

#ifdef NDEBUG
#   define DEBUG_ASSERT(...) 
#else
#   define DEBUG_ASSERT(...)	assert(__VA_ARGS__)
#endif

struct async_todo;
struct async_promise;
struct async_callback_queuer;
struct async_alien;

struct async_manager
{
	struct uc_async_manager header;

	uc_vm_t *vm;

	// Linked list of pending todo's
	struct async_todo *todo_list;
	// Points to the active promise which excecuting a then, catch or finally handler
	// to be able to catch the arguments of 'throw()'.
	struct async_promise *active_promise;

	// Number of pending promises
	int pending_promises_cnt:31;
    int silent:1; // exit is called, no more output

	// Pointer to linked list of async callback's
	struct async_callback_queuer *callback_queuer;

#ifdef ASYNC_HAS_UPTIME
	// For uptime
	int64_t start_time;
#endif
#ifdef ASYNC_HAS_ALIENS
	struct async_alien *alien;
#endif

	uc_resource_type_t *promise_type;
	uc_resource_type_t *timer_type;

	uint32_t refcount;
};

typedef struct async_manager async_manager_t;

#ifdef ASYNC_HAS_UPTIME
extern __hidden double 
async_manager_uptime( async_manager_t * );
#endif

static inline async_manager_t *
async_manager_cast( struct uc_async_manager *m )
{
	return (async_manager_t *)m;
}

static inline async_manager_t *
async_manager_get( uc_vm_t *vm )
{
	if( !vm )   return 0;
	struct uc_async_manager *manager = uc_async_manager_get( vm );
	if( !manager )
		return 0;
	return async_manager_cast( manager );
}

static inline async_manager_t *
async_manager_link( async_manager_t *manager )
{
	manager->refcount++;
	return manager;
}

static inline bool
async_manager_unlink( async_manager_t *manager )
{
	if( 0 == --manager->refcount )
	{
		free( manager );
		return true;
	}
	return false;
}

enum async_todo_type
{
	todoPromise = 1,
	todoTimer = 2,
	todoClearedTimer = todoTimer | 1,
};

typedef struct async_todo
{
	struct uc_async_timer header; // empty struct

	uint32_t todo_type : 2;

	/* refcount can be max 4.
	For promises: 1 for the ucode promise object,
			2 for the associated resolve,reject objects,
			and 1 for being in the todo list.
	For timers: 1 for the ucode timer object
			and 1 for being in the todo list.
	So 3 bits is plenty */
	uint32_t refcount : 3;
	/* One bit to know if this object is in the todo list */
	uint32_t in_todo_list : 1;

	/* which leaves 26 bits for general purpose: */
	uint32_t promise_pending : 1; // is added to 'global' vm->pending_promises_cnt
	uint32_t promise_state : 2;   // pending, resolved, rejected
	uint32_t promise_result_is_exception : 1;
	/* still 22 bits left */

	struct async_todo *next;
} async_todo_t;

extern __hidden void
async_todo_put_in_list( async_manager_t *manager, async_todo_t *todo);

extern __hidden int
async_todo_unlink( async_manager_t *manager, async_todo_t *todo);

#define reverse_stack(type, stack)		 \
	do									 \
	{									  \
		type *walk = stack, *reversed = 0; \
		while (walk)					   \
		{								  \
			type *pop = walk;			  \
			walk = pop->next;			  \
			pop->next = reversed;		  \
			reversed = pop;				\
		}								  \
		stack = reversed;				  \
	} while (0)


#endif // ndef UC_ASYNC_MANAGER_H
