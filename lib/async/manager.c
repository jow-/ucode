/*
 * Copyright (C) 2024 Isaac de Wolff <idewolff@vincitech.nl>
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

/**
 * # Async functions
 *
 * The `async` module provides asynchronous functionality.
 *
 * Functions can be individually imported and directly accessed using the
 * {@link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/import#named_import named import}
 * syntax:
 *
 *   ```
 *   import { Promise, setTimeout } from 'async';
 *
 *   Promise( (resolver)=>
 *   {
 *	   setTimeout( ()=>
 *	   {
 *		   resolver.resolve( 'done' );
 *	   }, 1000 )
 *   }).then( ( a )=>
 *   {
 *	   print( a );
 *   });
 *   ```
 *
 * Alternatively, the module namespace can be imported
 * using a wildcard import statement:
 *
 *   ```
 *   import * as async from 'async';
 *
 *   async.Promise( (resolver)=>
 *   {
 *	   async.setTimeout( ()=>
 *	   {
 *		   resolver.resolve( 'done' );
 *	   }, 1000 )
 *   }).then( ( a )=>
 *   {
 *	   print( a );
 *   }); 
 *   ```
 *
 * @module async
 */

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <assert.h>
#include <math.h>

#include "ucode/module.h"
#include "ucode/platform.h"
#include "ucode/async.h"

#include "manager.h"
#include "promise.h"
#include "callback.h"
#include "timer.h"

#ifdef HAS_UPTIME
static double
uptime( async_manager_t *manager )
{
	if (!manager)
		return NAN;
	int64_t now = async_timer_current_time() - manager->start_time;
	return (double)now / 1000.0;
}
#endif


/*******
 * The part of the code which is responsible for multithreaded asynchronity
 **/
#define SIGNEWCALLBACK SIGUSR1 // Signal used for async callbacks

/* There is max one instance of this struct per vm.
which is created when the first 'uc_async_callback_queuer' is created */
struct async_callback_unique_in_vm
{
	// linked list of callbacks to be executed
	struct async_callback_queuer_link *stack;
	int refcount;

	// Thread of the script
	pthread_t thread;
	// VM in which we live.
	async_manager_t *manager;
};

static uc_value_t *
async_callback_signal_handler(uc_vm_t *vm, size_t nargs)
{
	// Do nothing. We only want to interrupt the async_sleep function
#ifdef DEBUG_PRINT
	async_manager_t *manager = async_manager_get( vm );
	DEBUG_PRINTF( "%-1.3lf Signal handler\n", manager ? uptime(manager) : NAN );
#endif
	return 0;
}

static struct async_callback_unique_in_vm *
async_unique_in_vm_new( async_manager_t *manager )
{
	struct async_callback_unique_in_vm *unique = xalloc(sizeof(struct async_callback_unique_in_vm));
	unique->refcount = 1;

	// Setup signal handler
	uc_cfn_ptr_t ucsignal = uc_stdlib_function("signal");
	uc_value_t *func = ucv_cfunction_new("async", async_callback_signal_handler);

	uc_vm_stack_push( manager->vm, ucv_uint64_new( SIGNEWCALLBACK ));
	uc_vm_stack_push( manager->vm, func);

	if (ucsignal(manager->vm, 2) != func)
		fprintf(stderr, "Unable to install async_callback_signal_handler\n");

	ucv_put(uc_vm_stack_pop( manager->vm));
	ucv_put(uc_vm_stack_pop( manager->vm));
	ucv_put( func );

	// Remember the thread ID
	unique->thread = pthread_self();
	// And the vm
	unique->manager = manager;
	return unique;
}

static async_manager_t *
async_unique_is_synchron(struct async_callback_unique_in_vm *unique)
{
	if (unique->thread == pthread_self())
		return unique->manager;
	return 0;
}

/* Wakeup the sleeping script engine */
static void
async_unique_wakeup(struct async_callback_unique_in_vm *unique)
{
	if (async_unique_is_synchron( unique ) )
		// running in the script thread
		return;

	DEBUG_PRINTF( "%-1.3lf Wakeup script\n", uptime( unique->manager ) );
	// send a signal to the script thread;
	union sigval info = {0};
	info.sival_ptr = (void *)unique->thread;

	pthread_sigqueue(unique->thread, SIGNEWCALLBACK, info);
}

/* Start an interruptable sleep */
static void async_unique_sleep(struct async_callback_unique_in_vm *unique, int64_t msec)
{
	if (msec < 1)
		return;

	struct timespec wait;
	wait.tv_sec = msec / 1000;
	wait.tv_nsec = (msec % 1000) * 1000000;
	nanosleep(&wait, 0);
}

static int
async_unique_in_vm_link(struct async_callback_unique_in_vm *unique)
{
	return __atomic_add_fetch(&unique->refcount, 1, __ATOMIC_RELAXED);
}

static int
async_unique_in_vm_unlink(struct async_callback_unique_in_vm *unique)
{
	int refcount = __atomic_add_fetch(&unique->refcount, -1, __ATOMIC_RELAXED);
	if (refcount)
		return refcount;

	// TODO: Shouldn't we release the signal handler?

	free(unique);
	return refcount;
}

static struct async_callback_queuer_link *
uc_unique_lock_stack(struct async_callback_unique_in_vm *unique)
{
	struct async_callback_queuer_link **pstack = &unique->stack;
	/*
	The stack is locked as the least significant bit is 1.
	So we try to set it, which only succeeds if it is not set now.
	*/
	while (true)
	{
		struct async_callback_queuer_link *oldstack = *pstack;
		oldstack = (void *)(((intptr_t)oldstack) & ~(intptr_t)1);
		struct async_callback_queuer_link *newstack = oldstack;
		newstack = (void *)(((intptr_t)newstack) | (intptr_t)1);
		if (__atomic_compare_exchange_n(pstack, &oldstack, newstack, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
		{
			return oldstack;
		}
	}
}

static void
uc_unique_unlock_stack(struct async_callback_unique_in_vm *unique, struct async_callback_queuer_link *func)
{
	/*
	Unlock the stack by writing a 'clean' pointer, without bit 0 set.
	*/
	__atomic_store_n(&unique->stack, func, __ATOMIC_RELAXED);
}

/*******
 * End of multithreaded functions
 */



int
async_todo_unlink( async_manager_t *manager, async_todo_t *todo)
{
	if (!todo)
		return EXCEPTION_NONE;

	if (0 != --todo->refcount)
		return EXCEPTION_NONE;

	DEBUG_ASSERT( 0 == todo->in_todo_list );

	int ret = EXCEPTION_NONE;
	switch ((enum async_todo_type)todo->todo_type)
	{
	case todoClearedTimer:
	case todoTimer:
		async_timer_destroy( manager, todo );
		break;
	case todoPromise:
		ret = async_promise_destroy( manager, todo);
		break;
	}

	free(todo);
	return ret;
}

// When is the todo object due?
static inline int64_t
async_todo_due(async_todo_t *todo)
{
	switch ((enum async_todo_type)todo->todo_type)
	{
	case todoClearedTimer:
	case todoPromise:
		return 0;
	case todoTimer:
		return async_timer_cast(todo)->due;
	}
	return 0;
}

void
async_todo_put_in_list( async_manager_t *manager, async_todo_t *todo)
{
	DEBUG_ASSERT( 0 == todo->in_todo_list );
	todo->in_todo_list = 1;

	int64_t due = async_todo_due(todo);
	if( due )
	{
		DEBUG_PRINTF( "%-1.3lf Todo %p scheduled at %-1.3lf\n", uptime(manager), todo, 
			(due - manager->start_time) / 1000.0 );

	}
	async_todo_t *previous = 0;
	for (async_todo_t *it = manager->todo_list; it; it = it->next)
	{
		if (async_todo_due(it) > due)
		{
			todo->next = it;
			if (previous)
				previous->next = todo;
			else
				manager->todo_list = todo;
			todo->refcount++;
			return;
		}
		previous = it;
	}
	todo->next = 0;
	if (previous)
		previous->next = todo;
	else
		manager->todo_list = todo;
	todo->refcount++;
}

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

static int
async_handle_todo( async_manager_t *manager )
{
	if (!manager->todo_list)
		return EXCEPTION_NONE;
	int64_t now = async_timer_current_time();
	async_todo_t *to_be_handled = 0;

	while (manager->todo_list)
	{
		bool end_of_todo_for_now = false;
		switch ((enum async_todo_type)manager->todo_list->todo_type)
		{
		case todoClearedTimer:
			break;
		case todoTimer:
			end_of_todo_for_now = async_timer_cast(manager->todo_list)->due > now;
			break;
		case todoPromise:
			break;
		}
		if (end_of_todo_for_now)
			break;

		async_todo_t *pop = manager->todo_list;
		manager->todo_list = pop->next;
		pop->in_todo_list = 0;
		pop->next = 0;

		if (todoClearedTimer == pop->todo_type)
		{
			async_todo_unlink(manager, pop);
		}
		else
		{
			pop->next = to_be_handled;
			to_be_handled = pop;
		}
	}

	if (!to_be_handled)
		return EXCEPTION_NONE;

	reverse_stack(async_todo_t, to_be_handled);

	while (to_be_handled)
	{
		async_todo_t *pop = to_be_handled;
		to_be_handled = pop->next;
		pop->next = 0;
		int ex = EXCEPTION_NONE;

		switch ((enum async_todo_type)pop->todo_type)
		{
		case todoClearedTimer:
		{
			// The timer can be cleared in one of the previous to_be_handled functions
			break;
		}
		case todoTimer:
		{
			ex = async_timer_do(manager,pop);
			break;
		}
		case todoPromise:
		{
			ex = async_promise_do(manager, pop);
			break;
		}
		}

		{
			int ex2 = async_todo_unlink(manager, pop);
			if (EXCEPTION_NONE == ex)
				ex = ex2;
		}

		if (EXCEPTION_NONE != ex)
		{
			// put back all remaining todo's
			reverse_stack(async_todo_t, to_be_handled);
			while (to_be_handled)
			{
				async_todo_t *pop = to_be_handled;
				to_be_handled = pop->next;
				pop->next = manager->todo_list;
				manager->todo_list = pop;
				pop->in_todo_list = 1;
			}
			return ex;
		}
	}
	return EXCEPTION_NONE;
}

static int64_t
async_how_long_to_next_todo( async_manager_t *manager )
{
	while (manager->todo_list)
	{
		switch ((enum async_todo_type)manager->todo_list->todo_type)
		{
		case todoClearedTimer:
		{
			// remove from list
			async_todo_t *pop = manager->todo_list;
			manager->todo_list = pop->next;
			pop->next = 0;
			pop->in_todo_list = 0;
			async_todo_unlink(manager, pop);
			continue;
		}
		case todoPromise:
			return 0;
		case todoTimer:
		{
			int64_t now = async_timer_current_time();
			int64_t due = async_timer_cast(manager->todo_list)->due;
			if (due > now)
				return due - now;
			return 0;
		}
		}
	}

	// Nothing in todo list
	return -1;
}


struct async_callback_queuer_link
{
	struct async_callback_queuer_link *next;
	struct async_callback callback;
};

typedef struct
{
	struct uc_async_callback_queuer header;
	struct async_callback_unique_in_vm *unique_in_vm;
} async_callback_queuer_t;

static inline async_callback_queuer_t *
async_callback_queuer_cast(struct uc_async_callback_queuer *handler)
{
	return (async_callback_queuer_t *)handler;
}

static inline async_callback_queuer_t const *
async_callback_queuer_cast_const(struct uc_async_callback_queuer const *handler)
{
	return (async_callback_queuer_t const *)handler;
}

static int
async_handle_queued_callbacks( async_manager_t *manager )
{
	if( 0 == manager || 0 == manager->callback_queuer )
		return EXCEPTION_NONE;
	async_callback_queuer_t *l_queuer = async_callback_queuer_cast(manager->callback_queuer);
	struct async_callback_queuer_link *stack = uc_unique_lock_stack(l_queuer->unique_in_vm);
	uc_unique_unlock_stack(l_queuer->unique_in_vm, 0);

	if (0 == stack)
		return EXCEPTION_NONE;

	reverse_stack(struct async_callback_queuer_link, stack);

	while (stack)
	{
		struct async_callback_queuer_link *pop = stack;
		stack = pop->next;
		int ex = async_callback_call( manager, &pop->callback, 0, 0, 0, true);
		free( pop );
		if (EXCEPTION_NONE == ex)
			continue;
		if (stack)
		{
			// put remaining stack back
			struct async_callback_queuer_link *last = stack;
			reverse_stack(struct async_callback_queuer_link, stack);
			last->next = uc_unique_lock_stack(l_queuer->unique_in_vm);
			uc_unique_unlock_stack(l_queuer->unique_in_vm, stack);
		}
		return ex;
	}
	return EXCEPTION_NONE;
}

static bool
async_any_queued_callbacks_waiting( async_manager_t *manager )
{
	if (0 == manager || 0 == manager->callback_queuer)
		return false;
	async_callback_queuer_t *l_queuer = async_callback_queuer_cast(manager->callback_queuer);
	if ((intptr_t)l_queuer->unique_in_vm->stack & ~(intptr_t)3)
		return true;
	return false;
}

static bool
_uc_async_request_callback(struct uc_async_callback_queuer const *queuer,
						   int (*func)(struct uc_vm *, void *, int), void *user)
{
	struct async_callback_queuer_link *pfunc = xalloc(sizeof(struct async_callback_queuer_link));
	pfunc->callback.callback_type = callbackC_int_user_flags;
	pfunc->callback.c_int_user_flags.func = func;
	pfunc->callback.c_int_user_flags.user = user;

	const async_callback_queuer_t *l_queuer = async_callback_queuer_cast_const(queuer);

	struct async_callback_queuer_link *stack = uc_unique_lock_stack(l_queuer->unique_in_vm);

	if (stack == (struct async_callback_queuer_link *)l_queuer->unique_in_vm)
	{
		// vm doesn't exist anymore
		uc_unique_unlock_stack(l_queuer->unique_in_vm, stack);
		free(pfunc);
		return false;
	}

	pfunc->next = stack;
	uc_unique_unlock_stack(l_queuer->unique_in_vm, pfunc);

	async_unique_wakeup( l_queuer->unique_in_vm );
	return true;
}

static void
_uc_async_callback_queuer_free(struct uc_async_callback_queuer const **pqueuer)
{
	if (0 == pqueuer || 0 == *pqueuer)
		return;
	async_callback_queuer_t const *l_queuer = async_callback_queuer_cast_const(*pqueuer);
	*pqueuer = 0;

	struct async_callback_unique_in_vm *unique_in_vm = l_queuer->unique_in_vm;
	free((void *)l_queuer);
	async_unique_in_vm_unlink(unique_in_vm);
}

static int _async_put_todo_in_list( uc_vm_t *vm, void *user, int flags)
{
	async_todo_t *todo = user;
	async_manager_t *manager = async_manager_get( vm );

	if (flags & UC_ASYNC_CALLBACK_FLAG_EXECUTE)
	{
		async_todo_put_in_list( manager, todo );
	}
	if (flags & UC_ASYNC_CALLBACK_FLAG_CLEANUP)
	{
		async_todo_unlink( manager, todo );
	}
	return EXCEPTION_NONE;
}

static uc_async_timer_t *
_uc_async_create_timer(struct uc_async_callback_queuer const *queuer,
					   int (*cb)(uc_vm_t *, void *, int), void *user, uint32_t msec, bool periodic)
{
	async_timer_t *timer = async_timer_c_int_user_flags_new(0, cb, user);
	timer->due = async_timer_current_time() + msec;
	if (periodic)
		timer->periodic = msec;
	timer->header.refcount++;

	async_callback_queuer_t const *l_queuer = async_callback_queuer_cast_const(queuer);

	// are we synchron?
	async_manager_t *manager = async_unique_is_synchron(l_queuer->unique_in_vm);
	if (manager)
	{
		_async_put_todo_in_list( manager->vm, &timer->header, UC_ASYNC_CALLBACK_FLAG_EXECUTE | UC_ASYNC_CALLBACK_FLAG_CLEANUP);
	}
	else
	{
		_uc_async_request_callback(queuer, _async_put_todo_in_list, &timer->header );
	}

	return &timer->header.header;
}

static int
_async_free_timer(uc_vm_t *vm, void *user, int flags)
{
	uintptr_t v = (uintptr_t)user;
	bool clear = v & 1;
	v = v & ~((uintptr_t)1);
	async_timer_t *timer = (async_timer_t *)v;
	async_manager_t *manager = async_manager_get(vm);
	if (flags & UC_ASYNC_CALLBACK_FLAG_EXECUTE)
	{
		if (clear)
			async_timer_destroy( manager, &timer->header );
	}
	if (flags & UC_ASYNC_CALLBACK_FLAG_CLEANUP)
	{
		async_todo_unlink( async_manager_get(vm), &timer->header);
	}
	return EXCEPTION_NONE;
}

static void
_uc_async_free_timer(struct uc_async_callback_queuer const *queuer,
					 uc_async_timer_t **_pptimer, bool clear)
{
	async_callback_queuer_t const *l_queuer = async_callback_queuer_cast_const(queuer);
	async_timer_t **pptimer = (async_timer_t **)_pptimer;
	if (!pptimer || !*pptimer)
		return;
	async_timer_t *timer = *pptimer;
	*_pptimer = 0;

	// use bit 0 to store the clear flag
	if (clear)
	{
		timer = (async_timer_t *)(((uintptr_t)timer) | 1);
	}

	// are we synchron?
	async_manager_t *manager = async_unique_is_synchron(l_queuer->unique_in_vm);
	if (manager)
	{
		_async_free_timer( manager->vm, timer, UC_ASYNC_CALLBACK_FLAG_EXECUTE | UC_ASYNC_CALLBACK_FLAG_CLEANUP);
	}
	else
	{
		_uc_async_request_callback(queuer, _async_free_timer, timer);
	}
}

static async_callback_queuer_t *
async_callback_queuer_new()
{
	async_callback_queuer_t *pcallbackhandler = xalloc(sizeof(async_callback_queuer_t));
	pcallbackhandler->header.free = _uc_async_callback_queuer_free;
	pcallbackhandler->header.request_callback = _uc_async_request_callback;
	pcallbackhandler->header.create_timer = _uc_async_create_timer;
	pcallbackhandler->header.free_timer = _uc_async_free_timer;
	return pcallbackhandler;
}

static struct uc_async_callback_queuer const *
_uc_async_new_callback_queuer( struct uc_async_manager *_man )
{
	async_manager_t *manager = async_manager_cast( _man );
	if( 0 == manager )
		return 0;

	if (0 == manager->callback_queuer)
	{
		async_callback_queuer_t *pcallbackhandler = async_callback_queuer_new();
		manager->callback_queuer = &pcallbackhandler->header;
		pcallbackhandler->unique_in_vm = async_unique_in_vm_new(manager);
	}

	async_callback_queuer_t *l_queuer = async_callback_queuer_cast(manager->callback_queuer);
	struct async_callback_unique_in_vm *unique_in_vm = l_queuer->unique_in_vm;
	async_callback_queuer_t *pcallbackhandler = async_callback_queuer_new();
	async_unique_in_vm_link(unique_in_vm);
	pcallbackhandler->unique_in_vm = unique_in_vm;
	return &pcallbackhandler->header;
}

static void
async_callback_queuer_free( async_manager_t *manager, struct uc_async_callback_queuer *queuer)
{
	if (0 == queuer)
		return;
	async_callback_queuer_t *l_queuer = async_callback_queuer_cast(queuer);
	struct async_callback_queuer_link *stack = uc_unique_lock_stack(l_queuer->unique_in_vm);
	// write sentinel value meaning that callbacks are disabled forever
	uc_unique_unlock_stack(l_queuer->unique_in_vm, (void *)l_queuer->unique_in_vm);

	struct uc_async_callback_queuer const *pconsth = queuer;
	_uc_async_callback_queuer_free(&pconsth);

	// call all function on stack with exec=false to make them able to free up resources
	while (stack)
	{
		struct async_callback_queuer_link *pop = stack;
		stack = pop->next;
		async_callback_destroy( manager->vm, &pop->callback);
	}
}

static void
async_manager_free(uc_vm_t *vm, async_manager_t *manager)
{
	while (manager->todo_list)
	{
		async_todo_t *pop = manager->todo_list;
		manager->todo_list = pop->next;
		pop->next = 0;
		async_todo_unlink( manager, pop);
	}

	async_callback_queuer_free( manager, manager->callback_queuer);
	free(manager);
}

static int
async_event_pump( struct uc_async_manager *_man, unsigned max_wait, int flags)
{
	async_manager_t *manager = async_manager_cast( _man );

	if (flags & UC_ASYNC_PUMP_PUMP)
	{
		int64_t until = 0;
		if (UINT_MAX == max_wait)
		{
			until = INT64_MAX;
		}
		else if (max_wait)
		{
			until = async_timer_current_time() + max_wait;
		}

		do
		{
			DEBUG_PRINTF("%-1.3lf Pump!\n", uptime( manager ));
			int ex = async_handle_todo( manager );
			if (EXCEPTION_NONE != ex)
			{
				if (EXCEPTION_EXIT == ex)
                {
                    manager->silent = 1;
					return STATUS_EXIT;
                }
				return ERROR_RUNTIME;
			}

			ex = async_handle_queued_callbacks( manager );
			if (EXCEPTION_NONE != ex)
			{
				if (EXCEPTION_EXIT == ex)
                {
                    manager->silent = 1;
					return STATUS_EXIT;
                }
				return ERROR_RUNTIME;
			}

			int64_t tosleep = async_how_long_to_next_todo( manager );

			if (-1 == tosleep) // no todo list
			{
				if( 0 == manager->pending_promises_cnt ) // no pending promises
				{
					// Nothing to do anymore
					DEBUG_PRINTF("%-1.3lf Last!\n", uptime( manager ));
					break; // do {} while( )
				}
				tosleep = INT64_MAX;
			}

			if (max_wait && !async_any_queued_callbacks_waiting( manager ))
			{
				if ((unsigned)tosleep > max_wait)
					tosleep = max_wait;
				if (tosleep > 0)
				{
#ifdef DEBUG_PRINT					
					DEBUG_PRINTF("%-1.3lf Start wait\n", uptime( manager ));
					/* The printf could have eaten a signal. 
					So look if something was added to the async stack */
					if( !async_any_queued_callbacks_waiting( manager ) )
#endif
						async_unique_sleep(0, tosleep);
					DEBUG_PRINTF("%-1.3lf End wait\n", uptime( manager ));
				}
			}
		} while ((flags & UC_ASYNC_PUMP_CYCLIC) &&
				 (until > async_timer_current_time()));
	} // if( flags & UC_ASYNC_PUMP_PUMP )

	if (flags & UC_ASYNC_PUMP_CLEANUP)
	{
		uc_vm_t *vm = manager->vm;
		manager->vm = 0;
		uc_vm_registry_delete( vm, "async.manager" );
		async_manager_free( vm, manager );
	}

	return STATUS_OK;
}


/**
 * Event pump, in which the asynchronous functions are actually executed.
 * 
 * You can call this inside your program regularly, or at the end. 
 * When omitted the async functions will be called after the script 
 * has 'ended', by the vm.
 *
 * @function module:async#PumpEvents
 *
 * @param {Number} [timespan=null]
 * Timespan in msec. The function will keep pumping events until *timespan* 
 * msec has elapsed. When no timespan is provided, PumpEvents() will keep 
 * pumping until no timers are left and no active promises are around, 
 * or an exception occurs.
 * 
 * @param {Boolean} [single=false]
 * Flag to only pump once, and then 'sleep' *timespan* msec, or 
 * return at the moment the next event is due to be executed, 
 * whatever comes first.
 * This is usable if you want to do something between each stroke of the 
 * event pump:
 * ```
 * let promise = async.Promise( (resolver)=>{ resolver.resolve( 1 ) } );
 * for( let i=0; i<5; i++ )
 * {
 *	 promise = promise.then( (num)=>{ print(num); return ++num } );
 * }
 * 
 * while( async.PumpEvents( 1000, true ) )
 * {
 *	 print( ` *${async.uptime()}* ` );
 * }
 * // will output something like '*0.002* 1 *0.003* 2 *0.003* 3 *0.004* 4 *0.005* 5 *0.005*' 
 * // and then exit.
 * ```
 * But also
 * ```
 * let timer;
 * timer = async.setPeriodic( ( cnt )=>
 * {
 *	 if( ++cnt.cnt == 5 )
 *		 async.clearTimeout( timer );
 *	 print( cnt.cnt );
 * }, 100, { cnt: 0 } );
 * 
 * while( async.PumpEvents( 1000, true ) )
 * {
 *	 print( ` *${async.uptime()}* ` );
 * }
 * // will output something like '*0.101* 1 *0.201* 2 *0.301* 3 *0.401* 4 *0.501* 5' 
 * // and then exit.
 * ```
 * 
 * @return {Boolean} 
 * True if more events are (or will be) available, False if no more events are to be expected.
 * 
 * @example
 * async.setTimeout( ()=>{}, 10000 );
 * 
 * let count = 0;
 * while( async.PumpEvents( 1000 ) )
 * { 
 *	 print( `${++count} ` );
 * }
 * // Will output '1 2 3 4 5 6 7 9' and then exit. 
 * // Maybe '10' is also printed, depending on the exact timing.
 */

static uc_value_t *
PumpEvents(uc_vm_t *vm, size_t nargs)
{
	unsigned msec = UINT_MAX;
	int flags = UC_ASYNC_PUMP_CYCLIC | UC_ASYNC_PUMP_PUMP;
	uc_value_t *pmsec = uc_fn_arg(0);
	if (pmsec)
	{
		int64_t v = ucv_int64_get(pmsec);
		if (v > 0)
		{
			if (v < UINT_MAX)
				msec = (unsigned)v;
			else
				msec = UINT_MAX - 1;
		}
	}
	uc_value_t *psingle = uc_fn_arg(1);
	if (psingle)
	{
		bool v = ucv_boolean_get(psingle);
		if (v)
			flags &= ~UC_ASYNC_PUMP_CYCLIC;
	}

	async_manager_t *manager = async_manager_get( vm );
	if( !manager )
		return ucv_boolean_new(false);
	
	async_event_pump( &manager->header, msec, flags);

	if( manager->pending_promises_cnt ||
			manager->todo_list)
			return ucv_boolean_new(true);

	return ucv_boolean_new(false);
}


#ifdef HAS_UPTIME
/**
 * Returns the uptime of the script (since importing the async plugin), in seconds, 
 * with a milli seconds resolution.
 * (Actually a debug helper, but I decided to leave it)
 * 
 * @function module:async#uptime
 *
 * @returns {Number} 
 * Uptime in seconds.
 * 
 * @example
 * let timer
 * timer = async.setPeriodic( (a)=>
 * {
 *	 if( async.uptime() > 5 )
 *		 async.clearTimeout( timer );
 *	 print( `${async.uptime()} ` );
 * }, 1000 );
 * 
 * while( async.PumpEvents() );
 * // Will output something like '0.003 1.003 2.003 3.003 4.003 5.003' and then exit.
 */

static uc_value_t *
Uptime(uc_vm_t *vm, size_t args)
{
	async_manager_t *manager = async_manager_get( vm );
	return ucv_double_new(uptime(manager));
}
#endif

static const uc_function_list_t local_async_fns[] = {
	{"PumpEvents", PumpEvents},
#ifdef HAS_UPTIME
	{"uptime", Uptime},
#endif
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	if( async_manager_get( vm ) )
	// Initializing twice?
		return;

	async_manager_t *manager = xalloc(sizeof(async_manager_t));
	uc_value_t *uv_manager = ucv_resource_new(NULL, manager);
	uc_vm_registry_set(vm, "async.manager", uv_manager);
	manager->vm = vm;

	manager->header.event_pump = async_event_pump;
	manager->header.new_callback_queuer = _uc_async_new_callback_queuer;

	async_promise_init( manager, scope );
	async_timer_init( manager, scope );

	uc_function_list_register(scope, local_async_fns);

#ifdef HAS_UPTIME
	manager->start_time = async_timer_current_time();
#endif
}
