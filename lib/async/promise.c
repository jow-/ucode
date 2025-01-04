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

#include "ucode/lib.h"
#include "ucode/vm.h"
#include "ucode/types.h"

#include "promise.h"
#include "callback.h"
#include "timer.h"

enum
{
	promisePending = 0,

	promiseThen,
	promiseCatch,
	promiseFinally,
};

struct async_promise_method
{
	struct async_promise_method *next;
	struct async_callback callback;
};

typedef struct async_promise_method async_promise_method_t;

static void
uc_promise_func_free( async_manager_t *manager, async_promise_method_t *func)
{
	if (!func)
		return;
	async_callback_destroy( manager->vm, &func->callback);
	free(func);
}

static void
async_exception_clear( async_manager_t *manager, uc_exception_t *exception)
{
	exception->type = EXCEPTION_NONE;

	ucv_put(exception->stacktrace);
	exception->stacktrace = NULL;

	free(exception->message);
	exception->message = NULL;
}

static void
async_exception_free( async_manager_t *manager, uc_exception_t *exception)
{
	if (!exception)
		return;
	async_exception_clear( manager, exception);
	free(exception);
}

static void
async_exception_move( async_manager_t *manager, uc_exception_t *to, uc_exception_t *from)
{
	if (from && to)
	{
		to->type = from->type;
		from->type = EXCEPTION_NONE;
		to->stacktrace = from->stacktrace;
		from->stacktrace = 0;
		to->message = from->message;
		from->message = 0;
	}
}

static uc_exception_t *
async_exception_new( async_manager_t *manager, uc_exception_t *exception)
{
	uc_exception_t *ret = xalloc(sizeof(uc_exception_t));
	if (exception)
	{
		async_exception_move( manager, ret, exception);
	}
	return ret;
}

/**
 * Represents a promise object as returned by
 * {@link module:async#Promise|Promise()} or {@link module:async#PromiseAll|PromiseAll()}.
 *
 * @class module:async.promise
 * @hideconstructor
 *
 * @see {@link module:async#Promise|Promise()}
 *
 * @implements then(), catch() and finally()
 * 
 * @example
 *
 * const promise = async.Promise(…);
 *
 * promise.then( ()=>{} );
 * promise.catch( ()=>{} );
 * promise.finally( ()=>{} );
 */

async_promise_t *
uc_promise_new( async_manager_t *manager )
{
	async_promise_t *p = xalloc(sizeof(async_promise_t));
	p->header.refcount = 1;
	p->header.todo_type = todoPromise;
	p->manager = async_manager_link( manager );
	p->manager->pending_promises_cnt++;
	p->header.promise_pending = 1;

	DEBUG_PRINTF("%-1.3lf new promise %p %u\n", async_manager_uptime(manager), p, manager->pending_promises_cnt);
	return p;
}

static inline async_promise_t *
async_promise_cast(async_todo_t *todo)
{
	DEBUG_ASSERT(todoPromise == todo->todo_type);
	return (async_promise_t *)todo;
}

static void
async_promise_clear_result( async_manager_t *manager, async_promise_t *promise )
{
	if( !promise )
		return;
	ucv_put( promise->reject_caused_by );
	promise->reject_caused_by = 0;

	if (promise->header.promise_result_is_exception)
	{
		async_exception_free( manager, promise->result.exception);
		promise->header.promise_result_is_exception = 0;
		promise->result.exception = 0;
	}
	else
	{
		ucv_put( promise->result.value );
		promise->result.value = 0;
	}
}

static uc_chunk_t *
uc_vm_frame_chunk(uc_callframe_t *frame)
{
	return frame->closure ? &frame->closure->function->chunk : NULL;
}

static bool 
async_vm_raise_exception_caused_by( uc_vm_t *vm, uc_value_t *caused_by, int type, const char *err, intptr_t arg )
{
	uc_callframe_t *frame = 0;
	bool ret = false;
	if( caused_by && UC_CLOSURE == ucv_type(caused_by) ) 
	{
		uc_vector_grow(&vm->callframes);

		frame = &vm->callframes.entries[vm->callframes.count++];
		frame->closure = (uc_closure_t *)caused_by;
		frame->cfunction = NULL;
		frame->stackframe = vm->stack.count;
		frame->ip = uc_vm_frame_chunk(frame)->entries; /* that would point to the first instruction of the closure so the error message would point there as well */
		frame->ctx = NULL;
		frame->mcall = false;
	}
	if( vm->callframes.count )
	{
		// No exceptions without framestack. It will crash
		uc_vm_raise_exception(vm, type, err, arg );
		ret = true;
	}
	if( frame )
	{
		/* "pop" artifical callframe */
		vm->callframes.count--;
	}
	return ret;
}

int
async_promise_destroy( async_manager_t *manager, async_todo_t *todo)
{
	async_promise_t *promise = async_promise_cast(todo);
	uc_vm_t *vm = manager ? manager->vm : 0;
    async_manager_t *vm_is_active = vm ? manager : 0;

	if (vm_is_active && promise->header.promise_pending)
	{
		vm_is_active->pending_promises_cnt--;
		promise->header.promise_pending = 0;
	}

	DEBUG_PRINTF("%-1.3lf delete promise %p %d\n", async_manager_uptime(vm_is_active), promise, 
		vm_is_active ? vm_is_active->pending_promises_cnt : -1 );

	int ret = EXCEPTION_NONE;
	bool uncaught = promiseCatch == promise->header.promise_state;
	if (uncaught)
	{
		if (vm_is_active && promise->header.promise_result_is_exception)
		{
			// put back the original exception
			async_exception_clear( vm_is_active, &vm->exception);
			async_exception_move( vm_is_active, &vm->exception, promise->result.exception);
			async_exception_free( vm_is_active, promise->result.exception);
			promise->result.exception = 0;
			promise->header.promise_result_is_exception = 0;
			ret = vm->exception.type;
			uncaught = false;
		}
	}

	uc_value_t *caused_by = 0;
	if( uncaught )
	{
		caused_by = promise->reject_caused_by;
		promise->reject_caused_by = 0;
	}
	async_promise_clear_result( vm_is_active, promise );

	async_promise_method_t *stack = promise->stack;
	for (; stack;)
	{
		async_promise_method_t *pop = stack;
		stack = pop->next;

		if (vm_is_active && !(uncaught) && promiseFinally == pop->callback.type)
			async_callback_call( vm_is_active, &pop->callback, 0, 0, 0, false);
		async_callback_destroy( vm, &pop->callback);
		free(pop);
	}

	if (uncaught)
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
//#pragma GCC diagnostic ignored "-Wuse-after-free"
		static const char *err = "Rejected promise %p without catch handler\n";
		if (vm_is_active )
		{
			if( !async_vm_raise_exception_caused_by( vm, caused_by, ret = EXCEPTION_RUNTIME, err, (intptr_t)promise ) )
			{
				fprintf( stderr, err, promise);
			}
		}
		else
		{
            if( !manager || !manager->silent )
				fprintf( stderr, err, promise);
		}
#pragma GCC diagnostic pop
	}

	ucv_put( caused_by );
	return ret;
}

static void async_promise_method_pushback( async_manager_t *manager, async_promise_t *promise, async_promise_method_t *func)
{
	async_promise_method_t *previous = 0;
	for (async_promise_method_t *it = promise->stack; it; it = it->next)
	{
		previous = it;
	}
	if (previous)
		previous->next = func;
	else
		promise->stack = func;

	if (0 == promise->header.promise_pending)
	{
		promise->header.promise_pending = 1;
		manager->pending_promises_cnt++;
	}

	if ((0 == promise->header.in_todo_list) && 
		(promisePending != promise->header.promise_state))
	{
		async_todo_put_in_list( manager, &promise->header);
	}
}

static void
async_promise_add_ucode_func( async_manager_t *manager, async_promise_t *promise, uc_value_t *func, int type)
{
	if (!ucv_is_callable(func))
	{
		uc_vm_raise_exception(manager->vm, EXCEPTION_TYPE, "arg1 needs to be callable");
		return;
	}

	async_promise_method_t *pf = xalloc(sizeof(async_promise_method_t));
	pf->callback.type = type;
	pf->callback.callback_type = callbackUcode;
	pf->callback.ucode.func = ucv_get(func);
	pf->next = 0;

	async_promise_method_pushback(manager, promise, pf);
}

static void
async_promise_add_c_int_user_args_flags_func( async_manager_t *manager,
											async_promise_t *promise,
											int (*func)(uc_vm_t *, void *, uc_value_t **, size_t, int), void *user, int type)
{
	async_promise_method_t *pf = xalloc(sizeof(async_promise_method_t));
	pf->callback.type = type;
	pf->callback.callback_type = callbackC_int_user_args_flags;
	pf->callback.c_int_user_args_flags.func = func;
	pf->callback.c_int_user_args_flags.user = user;
	pf->next = 0;

	async_promise_method_pushback( manager, promise, pf);
}

struct async_promise_resolver
{
	uc_async_promise_resolver_t header; // empty struct
	uint32_t refcount : 16;
	uint32_t type : 16;
	async_promise_t *promise;
	uc_value_t *callback; // The callback provided with the creator: async.Promise( callback )
};

typedef struct async_promise_resolver async_promise_resolver_t;

static inline async_promise_resolver_t *
async_promise_resolver_cast( struct uc_async_promise_resolver *p )
{
	return (async_promise_resolver_t *)p;
}

static async_promise_resolver_t *
async_promise_resolver_new( async_promise_t *promise )
{
	async_promise_resolver_t *resolver = xalloc(sizeof(async_promise_resolver_t));
	resolver->refcount = 1;
	promise->header.refcount++;
	resolver->promise = promise;
	promise->resolver = &resolver->header;
	return resolver;
}

static const char *_strPromise = "async.promise";

static uc_value_t *
async_promise_then(uc_vm_t *vm, size_t nargs)
{
	async_promise_t **ppromise = uc_fn_this(_strPromise);
	if (!ppromise || !*ppromise)
		return 0;
	async_promise_add_ucode_func( (*ppromise)->manager, *ppromise, uc_fn_arg(0), promiseThen);
	return ucv_get(_uc_fn_this_res(vm));
}

static uc_value_t *
async_promise_catch(uc_vm_t *vm, size_t nargs)
{
	async_promise_t **ppromise = uc_fn_this(_strPromise);
	if (!ppromise || !*ppromise)
		return 0;
	async_promise_add_ucode_func( (*ppromise)->manager, *ppromise, uc_fn_arg(0), promiseCatch);
	return ucv_get(_uc_fn_this_res(vm));
}

static uc_value_t *
async_promise_finally(uc_vm_t *vm, size_t nargs)
{
	async_promise_t **ppromise = uc_fn_this(_strPromise);
	if (!ppromise || !*ppromise)
		return 0;
	async_promise_add_ucode_func( (*ppromise)->manager, *ppromise, uc_fn_arg(0), promiseFinally);
	return ucv_get(_uc_fn_this_res(vm));
}

static const uc_function_list_t promise_type_fns[] = {
	{"then", async_promise_then},
	{"catch", async_promise_catch},
	{"finally", async_promise_finally},
};

static void
close_promise(void *ud)
{
	async_promise_t *promise = ud;
	if (promise)
	{
		DEBUG_PRINTF("%-1.3lf close promise %p %u\n", async_manager_uptime(promise->manager), promise, promise->header.refcount);
		if( async_manager_unlink( promise->manager ) )
			promise->manager = 0;
		async_todo_unlink(promise->manager, &promise->header);
	}
}

int
async_promise_do( async_manager_t *manager, async_todo_t *todo)
{
	async_promise_t *promise = async_promise_cast(todo);

	int state = promise->header.promise_state;

	async_promise_method_t *next_to_be_handled = 0;
	// walk the stack searching for a handler
	for (; promise->stack;)
	{
		next_to_be_handled = promise->stack;
		promise->stack = next_to_be_handled->next;
		next_to_be_handled->next = 0;

		if (state == next_to_be_handled->callback.type  
			|| promiseFinally == next_to_be_handled->callback.type)
		{
			break;
		}

		uc_promise_func_free( manager, next_to_be_handled);
		next_to_be_handled = 0;
	}

	if( !next_to_be_handled )
	{
		// mark as 'not pending'
		if (promise->header.promise_pending)
		{
			promise->header.promise_pending = 0;
			if( manager ) manager->pending_promises_cnt--;
		}
		return EXCEPTION_NONE;
	}

	uc_value_t *out = 0;
	int ex = EXCEPTION_NONE;
	{
		uc_value_t *in = 0;
		if (promiseFinally != next_to_be_handled->callback.type)
		{
			if (promise->header.promise_result_is_exception)
			{
				in = ucv_string_new(promise->result.exception->message);
			}
			else
			{
				in = ucv_get( promise->result.value );
			}

			async_promise_clear_result( manager, promise );			
		}

		// reset the state, so we know when throw() is called
		promise->header.promise_state = promisePending;

		{
			async_promise_t *push = manager->active_promise;
			manager->active_promise = promise;
			ex = async_callback_call( manager, &next_to_be_handled->callback, &in, 1, &out, true);
			manager->active_promise = push;
		}

		ucv_put(in);
	}

	uc_value_t *caused_by = async_callback_get_ucode_func( manager, &next_to_be_handled->callback );
	int ittype = next_to_be_handled->callback.type;
	uc_promise_func_free( manager, next_to_be_handled);

	if (EXCEPTION_NONE != ex)
	{
		if (EXCEPTION_EXIT == ex)
		{
			ucv_put( caused_by );
			return ex;
		}
		ucv_put(out);
		ucv_put(promise->reject_caused_by);
		promise->reject_caused_by = caused_by;
		if( promiseCatch == promise->header.promise_state )
		{
			// Caused by a throw()
			async_exception_clear( manager, &manager->vm->exception );
		}
		else 
		{
			// Take over the exception
			promise->result.exception = async_exception_new( manager, &manager->vm->exception);
			promise->header.promise_result_is_exception = 1;
			promise->header.promise_state = promiseCatch;
		}
		// reschedule
		async_todo_put_in_list( manager, &promise->header );
		return EXCEPTION_NONE;
	}

	ucv_put(caused_by);
	caused_by = 0;

	if (promiseFinally == ittype)
	{
		// Return value of finally is ignored, if it's not an exception
		ucv_put(out);

		// put state back
		promise->header.promise_state = state;
		// reschedule
		async_todo_put_in_list( manager, &promise->header );
		return EXCEPTION_NONE;
	}

	{   // Is the result a promise?
		async_promise_t **ppromise = (async_promise_t **)ucv_resource_dataptr(out, _strPromise);
		if (ppromise && *ppromise)
		{
			async_promise_t *new_promise = *ppromise;
			// We must push it's handler stack in front of ours,
			// and adopt it's state and it's resolver
			async_promise_method_t *previous = 0;
			for (async_promise_method_t *it2 = new_promise->stack; it2; it2 = it2->next)
			{
				previous = it2;
			}
			if (previous)
				previous->next = promise->stack;
			else
				new_promise->stack = promise->stack;
			promise->stack = new_promise->stack;
			new_promise->stack = 0;

			if (promise->resolver)
			{
				// Shouldn't be possible, but handle anyway
				async_promise_resolver_cast( promise->resolver )->promise = 0;
				promise->resolver = 0;
				promise->header.refcount--;
			}

			if (new_promise->resolver)
			{
				async_promise_resolver_cast( new_promise->resolver )->promise = promise;
				promise->resolver = new_promise->resolver;
				new_promise->resolver = 0;
				new_promise->header.refcount--;
				promise->header.refcount++;
			}

			promise->result.value = new_promise->result.value;
			new_promise->result.value = 0;
			promise->header.promise_result_is_exception = new_promise->header.promise_result_is_exception;
			new_promise->header.promise_result_is_exception = 0;
			promise->header.promise_state = new_promise->header.promise_state;

			// destroys also new_promise
			ucv_put(out);

			if( promisePending == promise->header.promise_state )
			{
				// not reschedule. We must wait for the resolver to act
			}
			else 
			{
				// reschedule
				async_todo_put_in_list( manager, &promise->header );
			}

			return EXCEPTION_NONE;
		}
	}

	promise->header.promise_state = promiseThen;
	promise->result.value = out;
	promise->header.promise_result_is_exception = 0;
	// reschedule
	async_todo_put_in_list( manager, &promise->header );
	return EXCEPTION_NONE;
}

static void
async_resolve_or_reject( async_manager_t *manager, async_promise_resolver_t *resolver, uc_value_t *res, int type)
{
	if (!resolver || !resolver->promise)
		return;

	async_promise_t *promise = resolver->promise;
	resolver->promise = 0;
	promise->resolver = 0;

	if (promisePending != promise->header.promise_state)
	{
		async_todo_unlink( manager, &promise->header);
		return;
	}

	if (promiseThen == type)
		promise->header.promise_state = promiseThen;
	else if (promiseCatch == type)
		promise->header.promise_state = promiseCatch;

	promise->result.value = ucv_get(res);
	promise->header.promise_result_is_exception = 0;

	if( !promise->header.promise_pending )
	{
		promise->header.promise_pending = 1;
		manager->pending_promises_cnt++;
	}

	if (!promise->header.in_todo_list)
	{
		async_todo_put_in_list( manager, &promise->header);
	}

	async_todo_unlink( manager, &promise->header);
}

static int 
async_promise_resolver_unlink( async_manager_t *manager, async_promise_resolver_t *resolver )
{
	if( 0 == resolver || 0 != --resolver->refcount )
		return EXCEPTION_NONE;

	if (resolver->promise)
	{
		async_promise_t *promise = resolver->promise;
		resolver->promise = 0;
		promise->resolver = 0;

		DEBUG_PRINTF("%-1.3lf promise abandoned %p\n", async_manager_uptime(promise->manager), promise);
		promise->result.value = ucv_string_new("Promise abandoned");
		promise->header.promise_result_is_exception = 0;
		promise->header.promise_state = promiseCatch;
		promise->reject_caused_by = resolver->callback;
		resolver->callback = 0;
		if (promise->manager)
			async_todo_put_in_list(promise->manager, &promise->header);
		async_todo_unlink( promise->manager, &promise->header);
	}

	if( resolver->callback )
		ucv_put( resolver->callback );
	free(resolver);
	return EXCEPTION_NONE;
}

static uc_value_t *
async_resolver_resolve_or_reject( uc_vm_t *vm, size_t nargs, int type )
{
	uc_callframe_t *lastframe = uc_vector_last(&vm->callframes);
	if( !lastframe )
		return 0;
	uc_cfunction_t *callee = lastframe->cfunction;
	async_promise_resolver_t **presolver = (async_promise_resolver_t**)ucv_cfunction_ex_get_user( (uc_value_t *)callee );
	if( presolver )
	{
		async_promise_resolver_t *resolver = *presolver;
		if( resolver )
		{
			async_manager_t *manager = async_manager_get( vm );
			async_resolve_or_reject( manager, resolver, uc_fn_arg(0), type);
		}
	}
	return 0;
}
static uc_value_t *
async_resolver_resolve(uc_vm_t *vm, size_t nargs)
{
	return async_resolver_resolve_or_reject( vm, nargs, promiseThen );
}

static uc_value_t *
async_resolver_reject(uc_vm_t *vm, size_t nargs)
{
	return async_resolver_resolve_or_reject( vm, nargs, promiseCatch );
}

static void
async_resolver_destroy( uc_value_t *uv )
{
	async_promise_resolver_t **presolver = (async_promise_resolver_t**)ucv_cfunction_ex_get_user( uv );
	if( presolver )
	{
		async_promise_resolver_t *resolver = *presolver;
		*presolver = 0;
		if( resolver )
		{
			async_promise_resolver_unlink( 0, resolver );
		}
	}
}

static int
uc_resolver_immediate(uc_vm_t *vm, void *user, int flags)
{
	async_promise_resolver_t *resolver = user;
	async_manager_t *manager = async_manager_get( vm );
	int ex = EXCEPTION_NONE;
	if (flags & UC_ASYNC_CALLBACK_FLAG_EXECUTE)
	{
		uc_vm_stack_push(vm, ucv_get(resolver->callback));
		uc_value_t *resolve = ucv_cfunction_ex_new( "resolve", async_resolver_resolve, async_resolver_destroy, sizeof(resolver) );
		uc_value_t *reject = ucv_cfunction_ex_new( "reject", async_resolver_reject, async_resolver_destroy, sizeof(resolver) );
		
		async_promise_resolver_t **presolver = (async_promise_resolver_t**)ucv_cfunction_ex_get_user( resolve );
		resolver->refcount++;
		*presolver = resolver;
		
		presolver = (async_promise_resolver_t**)ucv_cfunction_ex_get_user( reject );
		resolver->refcount++;
		*presolver = resolver;

		uc_vm_stack_push(vm, resolve );
		uc_vm_stack_push(vm, reject );

		ex = uc_vm_call(vm, false, 2);

		if( EXCEPTION_NONE == ex )
			ucv_put(uc_vm_stack_pop(vm));
	}
	if (flags & UC_ASYNC_CALLBACK_FLAG_CLEANUP)
	{
		int ex2 = async_promise_resolver_unlink( manager, resolver );
		if( EXCEPTION_NONE == ex )
			ex = ex2;
	}
	return ex;
}

struct async_promise_array_result
{
	struct async_promise_array *promise_array;
	uc_value_t *value;
	int state; // only in use by ASYNC_PROMISE_ALLSETTLED
};

typedef enum {
	ASYNC_PROMISE_ALL = 1,
	ASYNC_PROMISE_ANY,
	ASYNC_PROMISE_RACE,
	ASYNC_PROMISE_ALLSETTLED,
} promise_array_type_t;

struct async_promise_array
{
	uint32_t refcount:9;
	uint32_t exec_refcount:9;
	uint32_t numresults: 8;
	uint32_t type : 4; // all, any, race, allsettled
	async_promise_resolver_t *resolver;
	
	struct async_promise_array_result results[];
};

static void async_promise_array_unlink(struct async_promise_array *promise_array)
{
	if (0 != --promise_array->refcount)
		return;
	for( uint32_t n=0; n<promise_array->numresults; n++ )
		ucv_put( promise_array->results[ n ].value );
	free(promise_array);
}

static int async_promise_array_resolve( async_manager_t *manager, struct async_promise_array *promise_array, uc_value_t **args, size_t nargs, int type)
{
	if( !promise_array->resolver )
		return EXCEPTION_NONE;

	if( promisePending == type )
	{
		DEBUG_PRINTF("%-1.3lf %p will be pending forever\n", async_manager_uptime(manager), promise_array->resolver);
		// to prevent it from keeping the script running forever, we'll remove it's 'promise pending' status
		async_promise_t *promise = promise_array->resolver->promise;
		if( promise )
		{
			if( promise->header.promise_pending )
			{
				manager->pending_promises_cnt--;
				promise->header.promise_pending = 0;
			}
			// and cleanup
			promise->resolver = 0;
			promise_array->resolver->promise = 0;
			async_todo_unlink( manager, &promise->header );
		}
	}
	else 
	{
		DEBUG_PRINTF("%-1.3lf %p resolved\n", async_manager_uptime(manager), promise_array->resolver);
		uc_value_t *value = 0;
		int value_type = 0;

		switch( (promise_array_type_t)promise_array->type )
		{
			case ASYNC_PROMISE_ALL:
				if( promiseCatch == type )
					value_type = 1;
				else if( promiseThen == type )
					value_type = 2;
				break;
			case ASYNC_PROMISE_ANY:
				if( promiseCatch == type )
					value_type = 2;
				else if( promiseThen == type )
					value_type = 1;
				break;
			case ASYNC_PROMISE_RACE:
				value_type = 1;
				break;
			case ASYNC_PROMISE_ALLSETTLED:
				value_type = 3;

		}
		switch( value_type )
		{
			case 1: // the provided argument in the current call
			{
				if( nargs > 0)
					value = args[0];
				break;
			}
			case 2: // the array of stored values
			{
				value = ucv_array_new_length( manager->vm, promise_array->numresults );
				for( uint32_t n=0; n<promise_array->numresults; n++ )
				{
					uc_value_t *elem = promise_array->results[ n ].value;
					promise_array->results[ n ].value = 0;
					if( elem )
						ucv_array_set( value, n, elem );
				}
				break;
			}
			case 3: // the array of stored values, as struct (for 'allsettled)
			{
				value = ucv_array_new_length( manager->vm, promise_array->numresults );
				uc_value_t *fullfilled = 0, *rejected = 0;
				for( uint32_t n=0; n<promise_array->numresults; n++ )
				{
					struct async_promise_array_result *result =
						&promise_array->results[ n ];
					uc_value_t *obj = ucv_object_new( manager->vm );
					ucv_get( obj );
					if( result->state == promiseCatch )
					{
						if( 0 == rejected ) rejected = ucv_string_new( "rejected" );
						ucv_object_add( obj, "status", ucv_get( rejected ) );
						ucv_object_add( obj, "reason", result->value );
						result->value = 0;
					}
					if( result->state == promiseThen )
					{
						if( 0 == fullfilled ) fullfilled = ucv_string_new( "fullfilled" );
						ucv_object_add( obj, "status", ucv_get( fullfilled ) );
						ucv_object_add( obj, "value", result->value );
						result->value = 0;
					}
					ucv_array_set( value, n, obj );
				}
				ucv_put( fullfilled );
				ucv_put( rejected );
				break;
			}
		}
		
		async_resolve_or_reject(manager, promise_array->resolver, value, type);
	}
	async_promise_resolver_unlink( manager, promise_array->resolver);
	promise_array->resolver = 0;
	return EXCEPTION_NONE;
}

static int async_promise_array_immediate(uc_vm_t *vm, void *user, int flags)
{
	/* When we come in this function, the array of promises didn't contain 
	any usable value. So what to do? */
	struct async_promise_array *promise_array = user;
	int ex = EXCEPTION_NONE;
	if (flags & UC_ASYNC_CALLBACK_FLAG_EXECUTE)
	{
		int type = 0;
		switch( (promise_array_type_t)promise_array->type )
		{
			case ASYNC_PROMISE_ALL:
				type = promiseThen;
				break;
			case ASYNC_PROMISE_ANY:
				type = promiseCatch;
				break;
			case ASYNC_PROMISE_RACE:
				/* According to the spec the promise should stay pending forever */
				type = promisePending;
				break;
			case ASYNC_PROMISE_ALLSETTLED:
				type = promiseThen;
				break;
		}
		ex = async_promise_array_resolve( async_manager_get( vm ), promise_array, 0, 0, type);
	}
	if (flags & UC_ASYNC_CALLBACK_FLAG_CLEANUP)
		async_promise_array_unlink(promise_array);
	return ex;
}

static int async_promise_array_then(uc_vm_t *vm, void *user, uc_value_t **args, size_t nargs, int flags)
{
	struct async_promise_array_result *result = user;
	struct async_promise_array *promise_array = result->promise_array;
	async_manager_t *manager = async_manager_get( vm );

	int ex = EXCEPTION_NONE;
	if (flags & UC_ASYNC_CALLBACK_FLAG_EXECUTE)
	{
		DEBUG_PRINTF("%-1.3lf promise_array_then()\n", async_manager_uptime(manager));
		result->state = promiseThen;
		int cnt = --promise_array->exec_refcount;
		switch( (promise_array_type_t)promise_array->type )
		{
			case ASYNC_PROMISE_ALL:
				if( nargs ) result->value = ucv_get( args[ 0 ] );
				break;
			case ASYNC_PROMISE_ANY:
				cnt = 0;
				break;
			case ASYNC_PROMISE_RACE:
				cnt = 0;
				break;
			case ASYNC_PROMISE_ALLSETTLED:
				if( nargs ) result->value = ucv_get( args[ 0 ] );
				break;
		}
		if( 0 == cnt )
			ex = async_promise_array_resolve( manager, promise_array, args, nargs, promiseThen);
	}
	if (flags & UC_ASYNC_CALLBACK_FLAG_CLEANUP)
	{
		async_promise_array_unlink(promise_array);
	}
	return ex;
}

static int async_promise_array_catch(uc_vm_t *vm, void *user, uc_value_t **args, size_t nargs, int flags)
{
	struct async_promise_array_result *result = user;
	struct async_promise_array *promise_array = result->promise_array;
	async_manager_t *manager = async_manager_get( vm );
	int ex = EXCEPTION_NONE;
	if (flags & UC_ASYNC_CALLBACK_FLAG_EXECUTE)
	{
		DEBUG_PRINTF("%-1.3lf promise_array_catch()\n", async_manager_uptime(manager));
		result->state = promiseCatch;
		int cnt = --promise_array->exec_refcount;
		switch( (promise_array_type_t)promise_array->type )
		{
			case ASYNC_PROMISE_ALL:
				cnt = 0;
				break;
			case ASYNC_PROMISE_ANY:
				if( nargs ) result->value = ucv_get( args[ 0 ] );
				break;
			case ASYNC_PROMISE_RACE:
				cnt = 0;
				break;
			case ASYNC_PROMISE_ALLSETTLED:
				if( nargs ) result->value = ucv_get( args[ 0 ] );
				break;
		}
		if( 0 == cnt )
			ex = async_promise_array_resolve(manager, promise_array, args, nargs, promiseCatch);
	}
	if (flags & UC_ASYNC_CALLBACK_FLAG_CLEANUP)
	{
		async_promise_array_unlink(promise_array);
	}
	return ex;
}

static uc_value_t *
async_promise_array_new( uc_vm_t *vm, size_t nargs, int type )
{
	uc_value_t *arr = uc_fn_arg(0);
	if (arr && arr->type != UC_ARRAY)
	{
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "arg1 needs to be an array");
		return 0;
	}

	size_t length = ucv_array_length(arr);
	if( length > 255 )
	{
		// promise_array->numresults has only 8 bits
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "arg1p[] may not exceed 255 elements");
		return 0;
	}

	async_manager_t *manager = async_manager_get( vm );
	if( !manager )
		return 0;

	struct async_promise_array *promise_array = 
		xalloc(sizeof(struct async_promise_array) + length * sizeof(struct async_promise_array_result));

	promise_array->type = type;
	async_promise_t *promise = uc_promise_new( manager );
	promise_array->resolver = async_promise_resolver_new(promise);

	for (size_t n = 0; n < length; n++)
	{
		uc_value_t *elem = ucv_array_get(arr, n);
		async_promise_t **ppromise = (async_promise_t **)ucv_resource_dataptr(elem, _strPromise);
		if (ppromise && *ppromise)
		{
			if( ASYNC_PROMISE_RACE == type &&
				((*ppromise)->header.promise_state != promisePending) &&
				(promisePending == promise->header.promise_state) )
			{
				// this one should fullfill the promise
				if( (*ppromise)->header.promise_result_is_exception )
				{
					promise->result.exception = (*ppromise)->result.exception;
					(*ppromise)->result.exception = 0;
					(*ppromise)->header.promise_result_is_exception = 0;
				}
				else 
				{
					promise->result.value = (*ppromise)->result.value;
					(*ppromise)->result.value = 0;
				}
				promise->header.promise_state = (*ppromise)->header.promise_state;
				promise_array->resolver->promise = 0;
				promise->resolver = 0;
				async_todo_unlink( manager, &promise->header );
				// Lets continue normally to keep the code simple
			}
			struct async_promise_array_result *slot = 
			&promise_array->results[ promise_array->numresults++ ];
			slot->promise_array = promise_array;
			promise_array->exec_refcount++;
			promise_array->refcount++;
			async_promise_add_c_int_user_args_flags_func( manager, *ppromise, async_promise_array_then, slot, promiseThen);
			promise_array->refcount++;
			async_promise_add_c_int_user_args_flags_func( manager, *ppromise, async_promise_array_catch, slot, promiseCatch);
		}
		else if( ASYNC_PROMISE_RACE == type )
		{
			if( promisePending == promise->header.promise_state )
			{
				// Promise should be resolved by this value
				promise->result.value = ucv_get( elem );
				promise->header.promise_state = promiseThen;
				promise_array->resolver->promise = 0;
				promise->resolver = 0;
				async_todo_unlink( manager, &promise->header );
			}
		}
		else if( ASYNC_PROMISE_ALLSETTLED == type )
		{
			// This value should simply show up as fullfilled:
			struct async_promise_array_result *slot = 
			&promise_array->results[ promise_array->numresults++ ];
			slot->promise_array = promise_array;
			slot->state = promiseThen;
			slot->value = ucv_get( elem );
		}
	}

	if (0 == promise_array->exec_refcount && 0 != promise_array->resolver->promise )
	{
		// Array didn't contain any promises. We will resolve in a 'setImmediate'.
		promise_array->refcount++;
		async_timer_t *timer = async_timer_c_int_user_flags_new( manager, async_promise_array_immediate, promise_array);
		async_todo_put_in_list( manager, &timer->header);
		timer->header.refcount--;
	}

	return uc_resource_new( manager->promise_type, promise);
}

static struct uc_value *
_uc_async_new_promise( struct uc_async_manager *_man, uc_async_promise_resolver_t **resolver)
{
	if( !resolver )
		return 0;
	async_manager_t *manager = async_manager_cast( _man );
	async_promise_t *promise = uc_promise_new( manager );
	*resolver = &async_promise_resolver_new(promise)->header;
	return uc_resource_new( manager->promise_type, promise);
}

static void
_uc_async_resolve_reject( struct uc_async_manager *_man, uc_async_promise_resolver_t **resolver, uc_value_t *res, bool resolve)
{
	if (!resolver || !*resolver)
		return;
	async_manager_t *manager = async_manager_cast( _man );
	async_promise_resolver_t *res2 = async_promise_resolver_cast(*resolver);
	*resolver = 0;
	async_resolve_or_reject( manager, res2, res, resolve ? promiseThen : promiseCatch);
	async_promise_resolver_unlink( manager, res2);
}

static char *uc_cast_string(uc_vm_t *vm, uc_value_t **v, bool *freeable) {
	if (ucv_type(*v) == UC_STRING) {
		*freeable = false;

		return _ucv_string_get(v);
	}

	*freeable = true;

	return ucv_to_string(vm, *v);
}

/**
 * Creates and returns a promise. The provided resolver function will be called 
 * asynchronously.
 *
 * @function module:async#Promise
 *
  * @param {Function} callback
 * The callback used to deliver the {?module:async.resolver} object.
 *
 * @returns {?module:async.promise}
 *
 * @example
 * // Create a promise
 * async Promise( (resolve,reject)=>
 * {
 *	 resolve( 'world' );
 *	 print( 'hello ' ); 
 * }).then( (a)=>
 * {
 *	 print( a );
 * });
 * // will output 'hello world'
 */

static uc_value_t *
Promise(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *func = uc_fn_arg(0);
	if (!ucv_is_callable(func))
	{
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "arg1 needs to be callable");
		return 0;
	}

	async_manager_t *manager = async_manager_get( vm );

	async_promise_t *promise = uc_promise_new( manager );
	async_promise_resolver_t *resolver = async_promise_resolver_new(promise);
	resolver->callback = ucv_get(func);

	async_timer_t *timer = async_timer_c_int_user_flags_new( manager, uc_resolver_immediate, resolver);
	async_todo_put_in_list( manager, &timer->header);
	timer->header.refcount--;
	
	return uc_resource_new( manager->promise_type, promise );
}

/**
 * Takes an array of {@link module:async.promise|promises}, and returns a single promise.
 * 
 * When one of the promises is rejected, the new promise is rejected immediately 
 * with the reject value.
 * When all of the promises are resolved, the new promise is resolved with an array
 * of the resolve values.
 *
 * @function module:async#PromiseAll
 *
 * @param {Array} promises
 * Array of {@link module:async.promise|promises}. Elements in the array which are no promise are ignored.
 * An empty array will cause the returned promise to be resolved immediately.
 *
 * @returns {?module:async.promise}
 *
 * @example
 * function NewPromise( interval, value, do_reject )
 * {
 *	 return async.Promise( (resolve,reject)=>
 *	 {
 *		  async.setTimeout( ()=>
 *		  {
 *			  if( do_reject ) reject( value );
 *			  resolve( value );
 *		  }, interval );
 *	 } );
 * }
 *
 * // Create an array of promises:
 * let promises = [ NewPromise(300,'A',false),
 *				  NewPromise(200,'B',false),
 *				  'hello',
 *				  NewPromise(400,'C',true) ];
 * 
 * async.PromiseAll( promises ).then( (a)=>
 * {
 *	 print( 'fullfilled ', a, '\n' );
 * }).catch( (a)=>
 * {
 *	 print( 'rejected ', a, '\n' );
 * });
 * // will output 'rejected C', however, if you change the boolean for 'C' in false,
 * // it will output 'fullfilled [ "A", "B", "C" ]'
 */

static uc_value_t *
PromiseAll(uc_vm_t *vm, size_t nargs)
{
	return async_promise_array_new( vm, nargs, ASYNC_PROMISE_ALL );
}

/**
 * Takes an array of {@link module:async.promise|promises}, and returns a single promise.
 * 
 * The first promise which resolves, resolves the new promise.
 * When none of the promises is resolved, the new promise will be rejected with
 * an array of reject objects.
 *
 * @function module:async#PromiseAny
 *
 * @param {Array} promises
 * Array of {@link module:async.promise|promises}. Elements in the array which are no promise are ignored.
 * An empty array will cause the returned promise to be rejected immediately.
 *
 * @returns {?module:async.promise}
 *
 * @example
 * function NewPromise( interval, value, do_reject )
 * {
 *	 return async.Promise( (resolve,reject)=>
 *	 {
 *		  async.setTimeout( ()=>
 *		  {
 *			  if( do_reject ) reject( value );
 *			  resolve( value );
 *		  }, interval );
 *	 } );
 * }
 *
 * // Create an array of promises:
 * let promises = [ NewPromise(300,'A',false),
 *				  NewPromise(200,'B',false),
 *				  'hello',
 *				  NewPromise(400,'C',true) ];
 * 
 * async.PromiseAny( promises ).then( (a)=>
 * {
 *	 print( 'fullfilled ', a, '\n' );
 * }).catch( (a)=>
 * {
 *	 print( 'rejected ', a, '\n' );
 * });
 * // will output 'fullfilled B', however, if you change the booleans for 'A' and 'B'
 * // in true, it will output 'rejected [ "A", "B", "C" ]'
 */

static uc_value_t *
PromiseAny(uc_vm_t *vm, size_t nargs)
{
	return async_promise_array_new( vm, nargs, ASYNC_PROMISE_ANY );
}

/**
 * Takes an array of {@link module:async.promise|promises}, and returns a single promise.
 * 
 * The first promise which settles, settles the new promise.
 * When the array of promises contains promises which are already settled,
 * or non-promise values, the new promise will settle with the first one of those 
 * in the array.
 *
 * @function module:async#PromiseRace
 *
 * @param {Array} promises
 * Array of {@link module:async.promise|promises}. An empty array will cause the returned 
 * promise to be pending forever.
 *
 * @returns {?module:async.promise}
 *
 * @example
 * function NewPromise( interval, value, do_reject )
 * {
 *	 return async.Promise( (resolve,reject)=>
 *	 {
 *		  async.setTimeout( ()=>
 *		  {
 *			  if( do_reject ) reject( value );
 *			  resolve( value );
 *		  }, interval );
 *	 } );
 * }
 *
 * // Create an array of promises:
 * let promises = [ NewPromise(300,'A',false),
 *				  NewPromise(200,'B',false),
 *				  'hello',
 *				  NewPromise(50,'C',true) ];
 * 
 * async.PromiseRace( promises ).then( (a)=>
 * {
 *	 print( 'fullfilled ', a, '\n' );
 * }).catch( (a)=>
 * {
 *	 print( 'rejected ', a, '\n' );
 * });
 * // will output 'fullfilled hello', however, if you remove the 'hello' value, 
 * // it will output 'rejected C'
 */

static uc_value_t *
PromiseRace(uc_vm_t *vm, size_t nargs)
{
	return async_promise_array_new( vm, nargs, ASYNC_PROMISE_RACE );
}

/**
 * Takes an array of {@link module:async.promise|promises}, and returns a single promise.
 * 
 * When all promises are settled, the new promise is fullfilled with an array of objects.
 * ```
 * {
 *	 status: 'fullfilled', // or 'rejected'
 *	 reason: 'whatever', // only set in case of 'rejected'
 *	 value: 'whatever' // only set in case of 'fullfilled'
 * }
 * ```
 * A non-promise value in the promise array will be 'fullfilled' in the result array.
 *
 * @function module:async#PromiseAllSettled
 *
 * @param {Array} promises
 * Array of {@link module:async.promise|promises}. 
 *
 * @returns {?module:async.promise}
 *
 * @example
 * function NewPromise( interval, value, do_reject )
 * {
 *	 return async.Promise( (resolve,reject)=>
 *	 {
 *		  async.setTimeout( ()=>
 *		  {
 *			  if( do_reject ) reject( value );
 *			  resolve( value );
 *		  }, interval );
 *	 } );
 * }
 *
 * // Create an array of promises:
 * let promises = [ NewPromise(300,'A',false),
 *				  NewPromise(200,'B',false),
 *				  'hello',
 *				  NewPromise(50,'C',true) ];
 * 
 * async.PromiseAllSettled( promises ).then( (a)=>
 * {
 *	 print( 'fullfilled ', a, '\n' );
 * }).catch( (a)=>
 * {
 *	 print( 'rejected ', a, '\n' );
 * });
 * // will output 'fullfilled [ { "status": "fullfilled", "value": "A" }, { "status": "fullfilled", "value": "B" }, { "status": "fullfilled", "value": "hello" }, { "status": "rejected", "reason": "C" } ]'
 */

static uc_value_t *
PromiseAllSettled(uc_vm_t *vm, size_t nargs)
{
	return async_promise_array_new( vm, nargs, ASYNC_PROMISE_ALLSETTLED );
}

/**
 * Helper function to make it possible to throw an object from a promise method.
 * 
 * When calling this function from within a promise method, the promise is rejected, and 
 * the provided argument is delivered in the next catch handler.
 * 
 * When called outside a promise method, async.throw( a ) is more or less a synonym of
 * die( \`${a}\` );
 *
 * @function module:async#throw
 *
 * @param {Any} error
 * Object or value to be delivered in the next catch handler
 * 
 * @throws {Error}
 * 
 * @example
 * async.Promise( (resolve,reject)=>{resolve('hello ')}).then((a)=>
 *	 print( a );
 *	 async.throw( 'world' );
 *	 print( 'this will never be printed' )
 * }).then( (a)=>
 * {
 *	 print( 'this will also never be printed' );
 * }).catch( (a)=>
 *	 print( a ) );
 * });
 * // Will output 'hello world'.
 */
 
static uc_value_t *
Throw( uc_vm_t *vm, size_t nargs )
{
	async_manager_t *manager = async_manager_get( vm );
	async_promise_t *promise = (0 == manager) ? 0 : manager->active_promise;

	if( promise )
	{
		// Throw being called from inside a promise
		promise->header.promise_state = promiseCatch;
		promise->result.value = ucv_get( uc_fn_arg(0) );
		promise->header.promise_result_is_exception = 0;
		
		// create a 'lightweight' exception, to prevent further code execution
		vm->exception.type = EXCEPTION_USER;
		return ucv_boolean_new( true );
	}

	// Create a 'fullblown' exception
	uc_value_t *v = uc_fn_arg(0);
	bool freeable = false;
	char *casted = uc_cast_string( vm, &v, &freeable );
	uc_vm_raise_exception( vm, EXCEPTION_USER, "%s", casted );
	if( freeable )
		free( casted );
	return ucv_boolean_new( false );
}

static const uc_function_list_t local_async_fns[] = {
	{"Promise", Promise},
	{"PromiseAll", PromiseAll},
	{"PromiseAny", PromiseAny},
	{"PromiseRace", PromiseRace},
	{"PromiseAllSettled",PromiseAllSettled},
	{"throw", Throw}
};

void async_promise_init( async_manager_t *manager, uc_value_t *scope )
{
	manager->header.new_promise = _uc_async_new_promise;
	manager->header.resolve_reject = _uc_async_resolve_reject;

	/* promise initializing */
	manager->promise_type = uc_type_declare(manager->vm, _strPromise, promise_type_fns, close_promise);

	uc_function_list_register(scope, local_async_fns);
}
