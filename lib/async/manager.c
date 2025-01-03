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
 *   Promise( (resolve,reject)=>
 *   {
 *	   setTimeout( ()=>
 *	   {
 *		   resolve( 'done' );
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
 *   async.Promise( (resolve,reject)=>
 *   {
 *	   async.setTimeout( ()=>
 *	   {
 *		   resolve( 'done' );
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
#include <time.h>
#include <assert.h>
#include <math.h>

#include "ucode/module.h"
#include "ucode/platform.h"
#include "ucode/async.h"

#include "manager.h"
#include "promise.h"
#include "callback.h"
#include "timer.h"
#include "queuer.h"
#include "alien.h"

#ifdef ASYNC_HAS_UPTIME
double
async_manager_uptime( async_manager_t *manager )
{
	if (!manager)
		return NAN;
	int64_t now = async_timer_current_time() - manager->start_time;
	return (double)now / 1000.0;
}
#endif

/* Start an interruptable sleep */
/*void async_sleep( async_manager_t *manager, int64_t msec)
{
	if (msec < 1)
		return;

	struct timespec wait;
	wait.tv_sec = msec / 1000;
	wait.tv_nsec = (msec % 1000) * 1000000;
	nanosleep(&wait, 0);
}*/

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

	ASYNC_ALIEN_TODO_INCREMENT( manager );

	int64_t due = async_todo_due(todo);
	if( due )
	{
		DEBUG_PRINTF( "%-1.3lf Todo %p scheduled at %-1.3lf\n", async_manager_uptime(manager), todo, 
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

static void
async_manager_cleanup(uc_vm_t *vm, async_manager_t *manager)
{
	while (manager->todo_list)
	{
		async_todo_t *pop = manager->todo_list;
		manager->todo_list = pop->next;
		pop->next = 0;
		async_todo_unlink( manager, pop);
	}

	{
		struct async_callback_queuer *queuer = manager->callback_queuer;
		manager->callback_queuer = 0;
		async_callback_queuer_free( manager, queuer );
	}
#ifdef ASYNC_HAS_ALIENS
	{
		async_alien_t *alien = manager->alien;
		manager->alien = 0;
		async_alien_free( manager, alien );
	}
#endif
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
			DEBUG_PRINTF("%-1.3lf Pump!\n", async_manager_uptime( manager ));
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
					
					IF_NO_MORE_ALIENS(manager)
					{
						// Nothing to do anymore
						DEBUG_PRINTF("%-1.3lf Last!\n", async_manager_uptime( manager ));
						break; // do {} while( )
					}
				}
				tosleep = INT64_MAX;
			}

			if (max_wait && !async_any_queued_callbacks_waiting( manager ))
			{
                ASYNC_ALIEN_LEAVE(manager);

				if ((unsigned)tosleep > max_wait)
					tosleep = max_wait;
				if (tosleep > 0)
				{
#ifdef DEBUG_PRINT					
					DEBUG_PRINTF("%-1.3lf Start wait\n", async_manager_uptime( manager ));
					/* The printf could have eaten a signal. 
					So look if something was added to the async stack */
					if( !async_any_queued_callbacks_waiting( manager ) )
#endif
						async_sleep( manager, tosleep);
					DEBUG_PRINTF("%-1.3lf End wait\n", async_manager_uptime( manager ));
				}

                ASYNC_ALIEN_ENTER(manager);
			}
            else
            {
                ASYNC_ALIEN_LEAVE(manager);
                ASYNC_ALIEN_ENTER(manager);
            }

		} while ((flags & UC_ASYNC_PUMP_CYCLIC) &&
				 (until > async_timer_current_time()));
	} // if( flags & UC_ASYNC_PUMP_PUMP )

	if (flags & UC_ASYNC_PUMP_CLEANUP)
	{
		uc_vm_t *vm = manager->vm;
		manager->vm = 0;
		async_manager_cleanup( vm, manager );
		uc_vm_registry_delete( vm, "async.manager" );
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
 * let promise = async.Promise( (resolve,reject)=>{ resolve( 1 ) } );
 * for( let i=0; i<5; i++ )
 * {
 *	 promise = promise.then( (num)=>{ print(num); return ++num } );
 * }
 * 
 * while( async.PumpEvents( 1000, true ) )
 * {
 *	 print( ` *${async.async_manager_uptime()}* ` );
 * }
 * // will output something like '*0.002* 1 *0.003* 2 *0.003* 3 *0.004* 4 *0.005* 5 *0.005*' 
 * // and then exit.
 * ```
 * But also
 * ```
 * let timer;
 * timer = async.setInterval( ( cnt )=>
 * {
 *	 if( ++cnt.cnt == 5 )
 *		 async.clearTimeout( timer );
 *	 print( cnt.cnt );
 * }, 100, { cnt: 0 } );
 * 
 * while( async.PumpEvents( 1000, true ) )
 * {
 *	 print( ` *${async.async_manager_uptime()}* ` );
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


#ifdef ASYNC_HAS_UPTIME
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
 * timer = async.setInterval( (a)=>
 * {
 *	 if( async.async_manager_uptime() > 5 )
 *		 async.clearTimeout( timer );
 *	 print( `${async.async_manager_uptime()} ` );
 * }, 1000 );
 * 
 * while( async.PumpEvents() );
 * // Will output something like '0.003 1.003 2.003 3.003 4.003 5.003' and then exit.
 */

static uc_value_t *
Uptime(uc_vm_t *vm, size_t args)
{
	async_manager_t *manager = async_manager_get( vm );
	return ucv_double_new(async_manager_uptime(manager));
}
#endif

static const uc_function_list_t local_async_fns[] = {
	{"PumpEvents", PumpEvents},
#ifdef ASYNC_HAS_UPTIME
	{"uptime", Uptime},
#endif
};

static void close_manager( void *ud )
{
	async_manager_t *manager = ud;
	DEBUG_PRINTF( "%-1.3lf close_manager( vm=%p )\n", async_manager_uptime( manager ), manager->vm );

	// Don't expect the vm to be useable anymore.
	manager->vm = 0;
	async_manager_cleanup( 0, manager );
	async_manager_unlink( manager );
}

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	if( async_manager_get( vm ) )
	// Initializing twice?
		return;

	async_manager_t *manager = xalloc(sizeof(async_manager_t));
	const uc_function_list_t manager_type_fns[0];
	uc_resource_type_t *managertype = uc_type_declare(vm, "async.manager", manager_type_fns, close_manager);
	uc_value_t *uv_manager = ucv_resource_new(managertype, async_manager_link( manager ) );
	uc_vm_registry_set(vm, "async.manager", uv_manager);
	manager->vm = vm;

	manager->header.event_pump = async_event_pump;

	async_promise_init( manager, scope );
	async_timer_init( manager, scope );
	async_callback_queuer_init( manager, scope );
	async_alien_init( manager, scope );

	uc_function_list_register(scope, local_async_fns);

#ifdef ASYNC_HAS_UPTIME
	manager->start_time = async_timer_current_time();
#endif
	DEBUG_PRINTF( "%-1.3lf uc_module_init( vm=%p )\n", async_manager_uptime( manager ), vm );
}
