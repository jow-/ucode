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
#include <signal.h>
#include <pthread.h>
#include <math.h>

#include "ucode/lib.h"
#include "ucode/vm.h"
#include "ucode/platform.h"
#include "ucode/async.h"

#include "manager.h"
#include "timer.h"
#include "queuer.h"


/*******
 * The part of the code which is responsible for multithreaded asynchronity
 **/
#define SIGNEWCALLBACK SIGUSR1 // Signal used for async callbacks
/*
static uc_value_t *
async_callback_signal_handler( uc_vm_t *vm, size_t nargs )
{
	// Do nothing. We only want to interrupt the async_sleep function
#ifdef DEBUG_PRINT
	async_manager_t *manager = async_manager_get( vm );
	DEBUG_PRINTF( "%-1.3lf Signal handler vm=%p\n", manager ? async_manager_uptime(manager) : NAN, vm );
#endif
	return 0;
}
*/
static async_manager_t *
async_callback_is_synchron( const async_callback_queuer_t *queuer )
{
	if (queuer->thread == pthread_self())
		return queuer->manager;
	return 0;
}

/* Wakeup the sleeping script engine */
static void
async_callback_queuer_wakeup( const async_callback_queuer_t *queuer )
{
	if (async_callback_is_synchron( queuer ) )
		// running in the script thread
		return;

	DEBUG_PRINTF( "%-1.3lf Wakeup script vm=%p\n", async_manager_uptime( queuer->manager ), queuer->manager->vm );
	// send a signal to the script thread;
	pthread_kill( queuer->thread, SIGNEWCALLBACK );
}

void async_sleep( async_manager_t *manager, int64_t msec )
{
	sigset_t waitset;
    struct timespec timeout;
 
    sigemptyset( &waitset );
    sigaddset( &waitset, SIGNEWCALLBACK );

	timeout.tv_sec = msec / 1000;
	timeout.tv_nsec = (msec % 1000) * 1000000;

   	sigtimedwait( &waitset, 0, &timeout );
}


static int
async_callback_queuer_addref( const async_callback_queuer_t *cqueuer, bool add )
{
	async_callback_queuer_t *queuer = (async_callback_queuer_t *)cqueuer;
	if( add )
		return __atomic_add_fetch(&queuer->refcount, 1, __ATOMIC_RELAXED);
	else
		return __atomic_add_fetch(&queuer->refcount, -1, __ATOMIC_RELAXED);
}

static struct async_callback_queuer_chain *
uc_async_queuer_lock_stack( const async_callback_queuer_t *cqueuer)
{
	async_callback_queuer_t *queuer = (async_callback_queuer_t *)cqueuer;
	struct async_callback_queuer_chain **pstack = &queuer->stack;
	/*
	The stack is locked as the least significant bit is 1.
	So we try to set it, which only succeeds if it is not set now.
	*/
	while (true)
	{
		struct async_callback_queuer_chain *oldstack = *pstack;
		oldstack = (void *)(((intptr_t)oldstack) & ~(intptr_t)1);
		struct async_callback_queuer_chain *newstack = oldstack;
		newstack = (void *)(((intptr_t)newstack) | (intptr_t)1);
		if (__atomic_compare_exchange_n( pstack, &oldstack, newstack, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
		{
			return oldstack;
		}
	}
}

static void
uc_async_queuer_unlock_stack( const async_callback_queuer_t *cqueuer, struct async_callback_queuer_chain *func)
{
	async_callback_queuer_t *queuer = (async_callback_queuer_t *)cqueuer;
	struct async_callback_queuer_chain **pstack = &queuer->stack;
	/*
	Unlock the stack by writing a 'clean' pointer, without bit 0 set.
	*/
	__atomic_store_n( pstack, func, __ATOMIC_RELAXED);
}

/*******
 * End of multithreaded functions
 */

struct async_callback_queuer_chain
{
	struct async_callback_queuer_chain *next;
	struct async_callback callback;
};

/*
static inline async_callback_queuer_t *
async_callback_queuer_cast(struct uc_async_callback_queuer *handler)
{
	return (async_callback_queuer_t *)handler;
}
*/

static inline async_callback_queuer_t const *
async_callback_queuer_cast_const(struct uc_async_callback_queuer const *handler)
{
	return (async_callback_queuer_t const *)handler;
}

int
async_handle_queued_callbacks( async_manager_t *manager )
{
	if( 0 == manager || 0 == manager->callback_queuer )
		return EXCEPTION_NONE;
	async_callback_queuer_t *queuer = manager->callback_queuer;
	struct async_callback_queuer_chain *stack = uc_async_queuer_lock_stack(queuer);
	uc_async_queuer_unlock_stack(queuer, 0);

	if (0 == stack)
		return EXCEPTION_NONE;

	reverse_stack(struct async_callback_queuer_chain, stack);

	while (stack)
	{
		struct async_callback_queuer_chain *pop = stack;
		stack = pop->next;
		int ex = async_callback_call( manager, &pop->callback, 0, 0, 0, true);
		free( pop );
		if (EXCEPTION_NONE == ex)
			continue;
		if (stack)
		{
			// put remaining stack back
			struct async_callback_queuer_chain *last = stack;
			reverse_stack(struct async_callback_queuer_chain, stack);
			last->next = uc_async_queuer_lock_stack(queuer);
			uc_async_queuer_unlock_stack(queuer, stack);
		}
		return ex;
	}
	return EXCEPTION_NONE;
}

bool
async_any_queued_callbacks_waiting( async_manager_t *manager )
{
	if (0 == manager || 0 == manager->callback_queuer)
		return false;
	async_callback_queuer_t *queuer = manager->callback_queuer;
	if ((intptr_t)queuer->stack & ~(intptr_t)3)
		return true;
	return false;
}

static bool
_uc_async_request_callback(struct uc_async_callback_queuer const *_queuer,
						   int (*func)(struct uc_vm *, void *, int), void *user)
{
	struct async_callback_queuer_chain *pfunc = xalloc(sizeof(struct async_callback_queuer_chain));
	pfunc->callback.callback_type = callbackC_int_user_flags;
	pfunc->callback.c_int_user_flags.func = func;
	pfunc->callback.c_int_user_flags.user = user;

	const async_callback_queuer_t *queuer = async_callback_queuer_cast_const(_queuer);

	struct async_callback_queuer_chain *stack = uc_async_queuer_lock_stack(queuer);

	if (stack == (struct async_callback_queuer_chain *)queuer )
	{
		// vm doesn't exist anymore
		uc_async_queuer_unlock_stack( queuer, stack);
		free(pfunc);
		return false;
	}

	pfunc->next = stack;
	uc_async_queuer_unlock_stack( queuer, pfunc);

	async_callback_queuer_wakeup( queuer );
	return true;
}

void
async_wakeup( const uc_async_callback_queuer_t *_queuer )
{
	if( !_queuer )
		return;
	const async_callback_queuer_t *queuer = async_callback_queuer_cast_const( _queuer );
	async_callback_queuer_wakeup( queuer );	
}


static void
_uc_async_callback_queuer_free(struct uc_async_callback_queuer const **pqueuer)
{
	if (0 == pqueuer || 0 == *pqueuer)
		return;
	async_callback_queuer_t const *queuer = async_callback_queuer_cast_const(*pqueuer);
	*pqueuer = 0;

	if( 0 == async_callback_queuer_addref( queuer, false ) )
	{
		if( 0 == queuer->manager )
			free( (void *)queuer );
	}
}

static int 
_async_put_todo_in_list( uc_vm_t *vm, void *user, int flags)
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
_uc_async_create_timer(struct uc_async_callback_queuer const *_queuer,
					   int (*cb)(uc_vm_t *, void *, int), void *user, uint32_t msec, bool periodic)
{
	async_timer_t *timer = async_timer_c_int_user_flags_new(0, cb, user);
	timer->due = async_timer_current_time() + msec;
	if (periodic)
		timer->periodic = msec;
	timer->header.refcount++;

	async_callback_queuer_t const *queuer = async_callback_queuer_cast_const(_queuer);

	// are we synchron?
	async_manager_t *manager = async_callback_is_synchron( queuer );
	if (manager)
	{
		_async_put_todo_in_list( manager->vm, &timer->header, UC_ASYNC_CALLBACK_FLAG_EXECUTE | UC_ASYNC_CALLBACK_FLAG_CLEANUP);
	}
	else
	{
		_uc_async_request_callback(_queuer, _async_put_todo_in_list, &timer->header );
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
_uc_async_free_timer(struct uc_async_callback_queuer const *_queuer,
					 uc_async_timer_t **_pptimer, bool clear)
{
	async_callback_queuer_t const *queuer = async_callback_queuer_cast_const(_queuer);
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
	async_manager_t *manager = async_callback_is_synchron( queuer );
	if (manager)
	{
		_async_free_timer( manager->vm, timer, UC_ASYNC_CALLBACK_FLAG_EXECUTE | UC_ASYNC_CALLBACK_FLAG_CLEANUP);
	}
	else
	{
		_uc_async_request_callback(_queuer, _async_free_timer, timer);
	}
}

static struct uc_async_callback_queuer const *
_uc_async_new_callback_queuer( struct uc_async_manager *_man )
{
	async_manager_t *manager = async_manager_cast( _man );
	if( 0 == manager )
		return 0;

	async_callback_queuer_t *queuer = manager->callback_queuer;
	if( 0 == queuer )
	{
		manager->callback_queuer = queuer = xalloc(sizeof(async_callback_queuer_t));

        sigset_t set;

        sigemptyset(&set);
		sigaddset(&set, SIGNEWCALLBACK );
		if( 0 != pthread_sigmask( SIG_BLOCK, &set, &queuer->oldmask ) )
		{
			perror( "pthread_sigmask" );
			exit( 1 );
		}

/*
		pthread_sigmask( )
		// Setup signal handler
		uc_cfn_ptr_t ucsignal = uc_stdlib_function("signal");
		uc_value_t *func = ucv_cfunction_new("async", async_callback_signal_handler);

		uc_vm_stack_push( manager->vm, ucv_uint64_new( SIGNEWCALLBACK ));
		uc_vm_stack_push( manager->vm, func);

		if (ucsignal(manager->vm, 2) != func)
			fprintf(stderr, "Unable to install async_callback_signal_handler\n");
		else
		{
			DEBUG_PRINTF("%-1.3lf vm=%p signal handler installed\n", async_manager_uptime(manager), manager->vm );

		}

		ucv_put(uc_vm_stack_pop( manager->vm));
		ucv_put(uc_vm_stack_pop( manager->vm));
		ucv_put( func );
*/

		// Remember the thread ID
		queuer->thread = pthread_self();
		// And the vm
		queuer->manager = async_manager_link( manager );

		queuer->header.free = _uc_async_callback_queuer_free;
		queuer->header.request_callback = _uc_async_request_callback;
		queuer->header.create_timer = _uc_async_create_timer;
		queuer->header.free_timer = _uc_async_free_timer;

		queuer->refcount = 1;
	}

	async_callback_queuer_addref( queuer, true );
	return &queuer->header;
}

void
async_callback_queuer_free( async_manager_t *manager, async_callback_queuer_t *queuer)
{
	if (0 == queuer)
		return;

	struct async_callback_queuer_chain *stack = uc_async_queuer_lock_stack( queuer );
	// write sentinel value meaning that callbacks are disabled forever
	uc_async_queuer_unlock_stack( queuer, (void *)queuer );

	async_manager_unlink( queuer->manager );
	queuer->manager = 0;

	struct uc_async_callback_queuer const *pconsth = &queuer->header;
	_uc_async_callback_queuer_free(&pconsth);

	// TODO: Shouldn't we release the signal handler?

	// call all function on stack with exec=false to make them able to free up resources
	while (stack)
	{
		struct async_callback_queuer_chain *pop = stack;
		stack = pop->next;
		async_callback_destroy( manager->vm, &pop->callback);
	}
}

void 
async_callback_queuer_init( async_manager_t *manager, uc_value_t *scope )
{
   	manager->header.new_callback_queuer = _uc_async_new_callback_queuer;
}

