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

/**
 * # Async function API
 *
 * The 'async' module provides asynchronous functionality.
 *
 * The c API of this module does not cause or need any linktime 
 * dependencies. All is handled via a struct uc_async_manager 
 * pointer in the uc_vm_t object, which is initialized in the
 * async.so uc_module_init() function, and which contains function pointers.
 * 
 * This file contains static inline wrapper functions.
 *
 * @module async
 */


#ifndef UCODE_ASYNC_H
#define UCODE_ASYNC_H
#include "types.h"
#include <limits.h>


/* This is the 'public' interface of the async module */
typedef struct uc_async_promise_resolver{} uc_async_promise_resolver_t;

typedef struct uc_async_timer {} uc_async_timer_t;

typedef struct uc_async_callback_queuer
{
    void (*free)( struct uc_async_callback_queuer const ** );

    bool (*request_callback)( struct uc_async_callback_queuer const *, 
            int (*)( uc_vm_t *, void *, int flags ), void * );

    uc_async_timer_t *(*create_timer)( struct uc_async_callback_queuer const *, 
            int (*)( uc_vm_t *, void *, int flags ), void *, uint32_t msec, bool periodic );

    void (*free_timer)( struct uc_async_callback_queuer const *, 
            uc_async_timer_t **, bool clear );
} uc_async_callback_queuer_t;

typedef struct uc_async_alien
{
    void (*free)( struct uc_async_alien const ** );
    int (*call)( const struct uc_async_alien *, int (*)( uc_vm_t *, void *, int flags ), void * );

    // Internally used, but you are free to queue your own callbacks with it.
    const uc_async_callback_queuer_t *queuer;
} uc_async_alient_t;

struct uc_async_manager
{
    // pump timers, promises and callbacks.
	int (*event_pump)( struct uc_async_manager *, unsigned max_wait, int flags );
 
    // promise functions
    struct uc_value *(*new_promise)( struct uc_async_manager *, struct uc_async_promise_resolver ** );
    void (*resolve_reject)( struct uc_async_manager *, struct uc_async_promise_resolver **, struct uc_value *, bool );

    // callback queuer functions
    uc_async_callback_queuer_t const *(*new_callback_queuer)( struct uc_async_manager * );

    // alien call function
    uc_async_alient_t const *(*new_alien)( struct uc_async_manager * );
};

/***
 * Function returns a pointer to an uc_async_manager if the async plugin is active. 
 * It is not active when it's not loaded, or when it has already finished.
 * */
static inline struct uc_async_manager *uc_async_manager_get( uc_vm_t *vm )
{
    if( !vm ) return 0;
    return (struct uc_async_manager *)ucv_resource_data(uc_vm_registry_get(vm, "async.manager"), NULL);
}

/**
 * Flags which are passed to a callback or timer function
 * When 'UC_ASYNC_CALLBACK_FLAG_EXECUTE' is set, 
 *   the function should do it's job.
 * When 'UC_ASYNC_CALLBACK_FLAG_CLEANUP' is set, 
 *   the function should cleanup resources. 
 *   The function will not be called again.
 * 
 * The flags can be set both in the same call. It is possible that 
 * 'UC_ASYNC_CALLBACK_FLAG_EXECUTE' will never be set, when the target
 * vm already ended. In that case the function will only be called once,
 * with the 'UC_ASYNC_CALLBACK_FLAG_CLEANUP' flag set.
 */
enum{
    UC_ASYNC_CALLBACK_FLAG_EXECUTE = 1,
    UC_ASYNC_CALLBACK_FLAG_CLEANUP = 2,
};

/**
 * Flags to be passed to vm->async_manager->pump_event().
 * Normally you'll not have to use them, the wrapper functions
 * will do.
 */
enum{
    UC_ASYNC_PUMP_PUMP = 1,
    UC_ASYNC_PUMP_CYCLIC = 2,
    UC_ASYNC_PUMP_CLEANUP = 4,
};

/**
 * Do one event pump cycle (handle all currently pending timers, callbacks and 
 * resolved promises) and then wait max <timeout> msec. The wait will be shorter
 * if either a timer is due, or a callback is requested.
 * 
 * So when the function returns before <timeout> msec have elapsed, a timer or 
 * callback is waiting.
*/
static inline int uc_async_pump_once( uc_vm_t *vm, unsigned timeout )
{
    struct uc_async_manager *manager = uc_async_manager_get( vm );
    if( !manager )
        return STATUS_OK;
    return (*manager->event_pump)( manager, timeout, UC_ASYNC_PUMP_PUMP );
}

/**
 * Pump events during <timeout> msec. 
*/
static inline int uc_async_pump_cyclic( uc_vm_t *vm, unsigned timeout )
{
    struct uc_async_manager *manager = uc_async_manager_get( vm );
    if( !manager )
        return STATUS_OK;
    return (*manager->event_pump)( manager, timeout, UC_ASYNC_PUMP_PUMP|UC_ASYNC_PUMP_CYCLIC );
}

/**
 * Create an (async) callback queuer. This queuer can queue callbacks to be 
 * executed in the script thread. 
 * 
 * This function has to be called from within the script thread.
 * 
 * The callback queuer can queue callbacks from any thread.
 * 
 * You have to call uc_async_callback_queuer_free() to cleanup resources. 
 * This can be done from any thread.
*/
static inline uc_async_callback_queuer_t const *uc_async_callback_queuer_new( uc_vm_t *vm )
{
    struct uc_async_manager *manager = uc_async_manager_get( vm );
    if( !manager )
        return 0;
    return (*manager->new_callback_queuer)( manager );
}

/**
 * Queue a callback to be executed in the script thread. 
 * It can be called from any thread, and will wake up the event pump.
 * If the function returns false, the callback is not queued because the 
 * target vm already stopped.
 * If the function returns true, the callback will be called.
 * When 'flags' has UC_ASYNC_CALLBACK_EXECUTE set, the callback should be executed,
 * when UC_ASYNC_CALLBACK_CLEANUP is set, you should free up resources in *user.
 * When only UC_ASYNC_CALLBACK_CLEANUP is set, 
 * it is possible the script is no longer running, and you shouldn't access vm.
*/
static inline bool 
uc_async_request_callback( 
    uc_async_callback_queuer_t const *queuer, 
    int (*cb)( uc_vm_t *vm, void *user, int flags ),
    void *user )
{
    if( !queuer )
        return false;
    return (*queuer->request_callback)( queuer, cb, user );
}

/**
 * The counterpart of setTimeout() and setInterval(). 
 * For the function flags see above.
 * 
 * The return value must eventually be free'd with uc_async_free_timer.
*/
static inline uc_async_timer_t *
uc_async_create_timer( 
    uc_async_callback_queuer_t const *queuer, 
    int (*cb)( uc_vm_t *vm, void *user, int flags ), 
    void *user, uint32_t msec, bool periodic )
{
    if( !queuer )
        return 0;
    return (*queuer->create_timer)( queuer, cb, user, msec, periodic );
}

/**
 * Free the timer object. 
 * If 'clear == true' this is the counterpart of clearTimeout().
 * If clear != true, the local resources are freed, but the timer 
 * is still active (if not expired yet). 
 * You will not have a way to stop the timer. The script will run until the 
 * timer expires, or forever if it's a periodic timer.
*/
static inline void 
uc_async_free_timer( 
    uc_async_callback_queuer_t const *queuer, 
    uc_async_timer_t **pptimer,
    bool clear )
{
    if( !queuer )
        return;      
    (*queuer->free_timer)( queuer, pptimer, clear );
}

/**
 * Cleanup the callback queuer. This function can be called from any thread.
*/
static inline void 
uc_async_callback_queuer_free( 
    uc_async_callback_queuer_t const **queuer )
{
    if( !queuer || !*queuer )
        return;
    (*(*queuer)->free)( queuer );
}

/**
 * Create a new promise. The return value is the promise,
 * and the reolver pointer will have a resolver handle.
 * 
 * This function has to be called from within the script thread.
*/
static inline uc_value_t *
uc_async_promise_new( uc_vm_t *vm, uc_async_promise_resolver_t **resolver )
{
    struct uc_async_manager *manager = uc_async_manager_get( vm );
    if( !manager )
        return 0;
    return (*manager->new_promise)( manager, resolver );
}

/**
 * Resolve the promise. The function will cleanup the resolver and 
 * reset the pointer.
 * You are not allowed to use the resolver again.
 * Normally you will call this function from a callback which is 
 * queued by a callback queuer.
*/
static inline void 
uc_async_promise_resolve( uc_vm_t *vm, uc_async_promise_resolver_t **resolver, uc_value_t *value )
{
    struct uc_async_manager *manager = uc_async_manager_get( vm );
    if( !manager )
        return;
    if( !resolver || !*resolver )
        return;
    (*manager->resolve_reject)( manager, resolver, value, true );
}

/**
 * Resolve the promise. The function will cleanup the resolver and 
 * reset the pointer.
 * You are not allowed to use the resolver again.
 * Normally you will call this function from a callback which is 
 * queued by a callback queuer.
*/
static inline void 
uc_async_promise_reject( uc_vm_t *vm, uc_async_promise_resolver_t **resolver, uc_value_t *value )
{
    struct uc_async_manager *manager = uc_async_manager_get( vm );
    if( !manager )
        return;
    if( !resolver || !*resolver )
        return;
    (*manager->resolve_reject)( manager, resolver, value, false );
}

/****
 * Create an 'alien' object, that is an object which can call script-native
 * function from an external thread
 * This function has to be called from the script thread.
 */
static inline const uc_async_alient_t *
uc_async_alien_new( uc_vm_t *vm )
{
    struct uc_async_manager *manager = uc_async_manager_get( vm );
    if( !manager )
        return 0;

    return (*manager->new_alien)( manager );
}

/****
 * Free the alien object. As long as an alien object is
 * around, the script will not finish
 */
static inline void
uc_async_alien_free( const uc_async_alient_t **alien )
{
    if( !alien || !*alien )
        return;
    (*(*alien)->free)( alien );
}

/****
 * Call a script function from another thread. This call will block if the
 * script is not in 'event pumping' mode.
 * The return value is the return value of func.
 * When the vm is already exited, or alien is NULL, the return value is INT_MIN
 */
static inline int 
uc_async_alien_call( const uc_async_alient_t *alien, int (*func)( uc_vm_t *, void *, int flags ), void *user )
{
    if( !alien )
        return INT_MIN;
    return (*alien->call)( alien, func, user );
}

/* 'private' interface. Designed to be called from vm.c */

/**
 * Pump events during <timeout> msec, or until event loop is empty, 
 * (UINT_MAX is forever), 
 * and then clean up the async module.
 * 
 * This function is designed to run in uc_vm_execute(), 
 * after the internal uc_vm_execute_chunk(),
 * to keep the event pump active until all promises are resolved 
 * and no more timers are active.
 * 
 * The return value is the new status.
*/
static inline int uc_async_finish( uc_vm_t *vm, int status, unsigned timeout )
{
    if( STATUS_OK != status )
        return status;
    struct uc_async_manager *manager = uc_async_manager_get( vm );
    if( !manager )
        return status;
    return (*manager->event_pump)( manager, timeout, UC_ASYNC_PUMP_PUMP|UC_ASYNC_PUMP_CYCLIC|UC_ASYNC_PUMP_CLEANUP );
}

#endif // UCODE_ASYNC_H