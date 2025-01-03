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

#include "manager.h"
#include "callback.h"
#include "timer.h"

/**
 * Represents a timer object as returned by
 * {@link module:async#setTimeout|setTimeout()}, {@link module:async#setInterval|setInterval()} or {@link module:async#setImmediate|setImmediate()}.
 *
 * This class has no methods. The only sane usage is to pass it to {@link module:async#clearTimeout|clearTimeout()}
 * 
 * @class module:async.timer
 * @hideconstructor
 *
 */
// async_timer_t

int64_t
async_timer_current_time();

static async_timer_t *
uc_timer_ucode_new( async_manager_t *manager, size_t nargs, uc_value_t *cb, size_t startarg)
{
	size_t n_args = nargs - startarg;
	async_timer_t *timer = xalloc(sizeof(async_timer_t) + n_args * sizeof(uc_value_t *));
	timer->header.refcount = 1;
	timer->header.todo_type = todoTimer;
	timer->callback.callback_type = callbackUcode;
	timer->callback.nargs = n_args;
	timer->callback.ucode.func = ucv_get(cb);
	uc_vm_t *vm = manager->vm;

	for (size_t n1 = startarg, n2 = 0; n1 < nargs; n1++, n2++)
		timer->callback.args[n2] = ucv_get(uc_fn_arg(n1));

	return timer;
}

async_timer_t *
async_timer_c_int_user_flags_new( async_manager_t *manager, int (*func)(uc_vm_t *, void *, int), void *user)
{
	async_timer_t *timer = xalloc(sizeof(async_timer_t));
	timer->header.refcount = 1;
	timer->header.todo_type = todoTimer;
	timer->callback.callback_type = callbackC_int_user_flags;
	timer->callback.c_int_user_flags.func = func;
	timer->callback.c_int_user_flags.user = user;
	return timer;
}

void 
async_timer_destroy( async_manager_t *manager, async_todo_t *todo )
{
    if( !todo )
        return;
    async_timer_t *timer = async_timer_cast( todo );
    timer->header.todo_type = todoClearedTimer;
	timer->due = 0;
	timer->periodic = 0;

    async_callback_destroy( manager ? manager->vm : 0, &timer->callback );
}

int 
async_timer_do( async_manager_t *manager, async_todo_t *todo )
{
    async_timer_t *timer = async_timer_cast(todo);
    int ex = async_callback_call(manager, &timer->callback, 0, 0, 0, false);
    if (0 == timer->periodic ||
        // the timer can be cleared in the callback itself
        todoClearedTimer == timer->header.todo_type)
        return ex;
    timer->due += timer->periodic;
    async_todo_put_in_list(manager, &timer->header);
    return ex;
}

int64_t
async_timer_current_time()
{
	struct timespec monotime;
	clock_gettime(CLOCK_MONOTONIC, &monotime);
	return ((int64_t)monotime.tv_sec) * 1000 + (monotime.tv_nsec / 1000000);
}


enum
{
	timerTimeout = 0,
	timerPeriodic,
	timerImmediate,
};

static const char *_strTimer = "async.timer";

static void
close_timer(void *p)
{
	async_timer_t *timer = p;
	if (timer)
	{
		async_todo_unlink(0, &timer->header);
	}
}

static uc_value_t *
createTimer(uc_vm_t *vm, size_t nargs, int type)
{
	uc_value_t *cb = uc_fn_arg(0);
	if (!ucv_is_callable(cb))
	{
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "arg1 needs to be callable");
		return 0;
	}
	int64_t timeout = 0;
	if (nargs > 1 && timerImmediate != type)
	{
		uc_value_t *arg2 = uc_fn_arg(1);
		timeout = ucv_int64_get(arg2);
	}
	else if (timerPeriodic == type)
	{
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "arg2 needs to be a number");
		return 0;
	}

	if (timerPeriodic == type && timeout < 1)
		timeout = 1;

	size_t startarg = 2;
	if (timerImmediate == type)
		startarg = 1;

	async_manager_t *manager = async_manager_get( vm );

	async_timer_t *timer = uc_timer_ucode_new( manager, nargs, cb, startarg);

	timer->periodic = (timerPeriodic == type) ? timeout : 0;

	if (timerImmediate == type)
	{
		timer->due = 0;
	}
	else
	{
		timer->due = async_timer_current_time() + timeout;
	}

	async_todo_put_in_list(manager, &timer->header);
	timer->header.refcount--;

	if (0 == manager->timer_type)
	{
		static const uc_function_list_t timer_fns[] = {};
		manager->timer_type = uc_type_declare(vm, _strTimer, timer_fns, close_timer);
	}

	timer->header.refcount++;
	return uc_resource_new(manager->timer_type, timer);
}

/**
 * Start a timer, to execute it's callback after a delay.
 * 
 * The timer can be stopped before the callback is executed using clearTimeout()
 * 
  * @function module:async#setTimeout
 *
 * @param {Function} callback
 * 
 * @param {Number} [interval = 0]
 * Optional time to be waited (in msec) before the callback is called.
 * 
 * @param {Any} ...args
 * Optional Argument(s) to be passed to the callback function.
 * 
 * @returns {?module:async.timer}
 * 
 * @example
 * async.setTimeout( (a)=>
 * {
 *	 print( a );
 * }, 10000, 'hello world' );
 * 
 * while( async.PumpEvents() );
 * // Will output 'hello world' after 10 seconds, and then exit.
 */

static uc_value_t *
setTimeout(uc_vm_t *vm, size_t nargs)
{
	return createTimer(vm, nargs, timerTimeout);
}

/**
 * Start a periodic timer, to execute it's callback at each interval.
 * 
 * The timer can be stopped using clearTimeout()
 * 
 * @function module:async#setInterval
 *
 * @param {Function} callback
 * 
 * @param {Number} interval
 * Interval time in millisec.
 * 
 * @param {Any} ...args
 * Optional Argument(s) to be passed to the callback function.
 * 
 * @returns {?module:async.timer}
 * 
 * @example
 * async.setInterval( (a)=>
 * {
 *	 print( `${++a.count}\n` );
 * }, 1000, { count: 0 } );
 * 
 * while( async.PumpEvents() );
 * // Will output '1\n2\n3\n...' forever.
 */

static uc_value_t *
setInterval(uc_vm_t *vm, size_t nargs)
{
	return createTimer(vm, nargs, timerPeriodic);
}

/**
 * Let callback be executed in the next event pump stroke.
 * 
 * In theory it can be stopped using clearTimeout()
 * 
 * A *setImmediate()* is executed before *setTimeout( ()=>{}, 0 )*. 
 * Background: the setTimeout() is scheduled at *now + 0 msec*, 
 * while 'setImmediate()' is scheduled at *start of time*, 
 * which has already passed.
 * 
 * @function module:async#setImmediate
 *
 * @param {Function} callback
 * 
 * @param {Any} ...args
 * Optional Argument(s) to be passed to the callback function.
 * 
 * @returns {?module:async.timer}
 * 
 * @example
 * async.setTimeout( (a)=>
 * {
 *	 print( a );
 * }, 0, 'world' );
 * async.setImmediate( (a)=>
 * {
 *	 print( a );
 * }, 'hello ' );
 *
 * while( async.PumpEvents() );
 * // Will output 'hello world', and exit.
 */

static uc_value_t *
setImmediate(uc_vm_t *vm, size_t nargs)
{
	return createTimer(vm, nargs, timerImmediate);
}

/**
 * Clears a timer. It's safe to call it more than once on the same timer object.
 * 
 * @function module:async#clearTimeout
 *
 * @param {?module:async.timer} timer
 * 
 * @returns {Boolean} 
 * True if the timer is a valid timer object, and false if it isn't.
 * 
 * @example
 * let timer = async.setTimeout( (a)=>
 * {
 *	 print( 'hello world' );
 * }, 1000 );
 * async.clearTimeout( timer );
 * while( async.PumpEvents() );
 * // Will output nothing, and exit immediately.
 */

static uc_value_t *
clearTimeout(uc_vm_t *vm, size_t nargs)
{
	async_timer_t **ptimer = (async_timer_t **)ucv_resource_dataptr(uc_fn_arg(0), _strTimer);
	if (ptimer && *ptimer)
	{
		async_timer_t *timer = *ptimer;
        async_manager_t *manager = async_manager_get( vm );
        async_timer_destroy( manager, &timer->header );
		return ucv_boolean_new(true);
	}
	return ucv_boolean_new(false);
}

static const uc_function_list_t local_async_fns[] = {
	{"setTimeout", setTimeout},
	{"setInterval", setInterval},
	{"setImmediate", setImmediate},
	{"clearTimeout", clearTimeout},
};

void 
async_timer_init( async_manager_t *manager, uc_value_t *scope )
{
   	uc_function_list_register(scope, local_async_fns);
}
