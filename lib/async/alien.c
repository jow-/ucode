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
#include <linux/futex.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <limits.h>

#include "ucode/lib.h"
#include "ucode/vm.h"
#include "ucode/types.h"
#include "ucode/async.h"

#include "manager.h"
#include "callback.h"
#include "alien.h"
#include "queuer.h"

#ifdef ASYNC_HAS_ALIENS

static int
async_futex(uint32_t *uaddr, int futex_op, uint32_t val,
    const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val,
                          timeout, uaddr2, val3);
}

static void 
async_alien_enter_futex( uint32_t *futex_addr )
{
    while (1) 
    {
        const uint32_t zero = 0;
        if( atomic_compare_exchange_strong( futex_addr, &zero, 1 ) )
            return;

        int futex_rc = async_futex(futex_addr, FUTEX_WAIT, 0, NULL, NULL, 0);
        if (futex_rc == -1) 
        {
            if (errno != EAGAIN) 
            {
                perror("futex wait");
                exit(1);
            }
        } 
    }

}

void
async_alien_enter( async_manager_t *manager )
{
    if( !manager->alien )
        return;
    async_alien_enter_futex( &manager->alien->the_futex );
}

static void
async_alien_release_futex( uint32_t *futex_addr )
{
    const uint32_t zero = 0;
    atomic_store( futex_addr, zero );
    if( -1 == async_futex(futex_addr, FUTEX_WAKE, 0, NULL, NULL, 0) )
    {
        perror( "futex wake" );
        exit( 1 );
    }
}

void
async_alien_release( async_manager_t *manager )
{
    if( !manager->alien )
        return;
    async_alien_release_futex( &manager->alien->the_futex );
}

static async_alien_t *
async_alien_cast( const struct uc_async_alien *_a )
{
    return (async_alien_t *)_a;
}


static void 
_uc_async_alien_free( struct uc_async_alien const ** palien )
{
    if( 0 == palien || 0 == *palien )
        return;
    async_alien_t *alien = async_alien_cast( *palien );
    *palien = 0;

    async_alien_enter_futex( &alien->the_futex );

    if( 0 == --alien->refcount )
    {
        if( alien->manager )
        {
            async_wakeup( alien->header.queuer );
        }
        else 
        {
            uc_async_callback_queuer_free( &alien->header.queuer );
            free( alien );
            return;
        }
    }

    async_alien_release_futex( &alien->the_futex );
}

static int 
_uc_async_alien_call( const struct uc_async_alien *_alien, int (*func)( uc_vm_t *, void *, int flags ), void *user )
{
    if( !_alien )
        return INT_MIN;

    async_alien_t *alien = async_alien_cast( _alien );

    async_alien_enter_futex( &alien->the_futex );
    if( !alien->manager )
    {
        // vm already stopped
        async_alien_release_futex( &alien->the_futex );
        return INT_MIN;
    }

    int todo_seq_before = alien->todo_seq;
    uc_thread_context_t *push = uc_thread_context_exchange( alien->thread_context );
    uc_vm_t *other_vm = alien->thread_context->signal_handler_vm;
    alien->thread_context->signal_handler_vm = push ? push->signal_handler_vm : 0;

    int ret = (func)( alien->manager->vm, user, UC_ASYNC_CALLBACK_FLAG_EXECUTE|UC_ASYNC_CALLBACK_FLAG_CLEANUP );

    uc_thread_context_exchange( push );
    alien->thread_context->signal_handler_vm = other_vm;

    if( todo_seq_before != alien->todo_seq )
    {
        // Something is added to the todolist. 
        // Wakeup script thread to let it reconsider it's sleep duration
        async_wakeup( alien->header.queuer );
    }

    async_alien_release_futex( &alien->the_futex );
    return ret;
}

static const uc_async_alient_t *
_uc_async_new_alien( struct uc_async_manager *_manager )
{
    async_manager_t *manager = async_manager_cast( _manager );
    async_alien_t *alien = manager->alien;
    if( 0 == alien )
    {
        alien = manager->alien = xalloc( sizeof( struct async_alien ) );
        alien->thread_context = uc_thread_context_get();
        alien->the_futex = 1;
        alien->manager = async_manager_link( manager );
        alien->header.queuer = manager->header.new_callback_queuer( &manager->header );
        alien->header.free = _uc_async_alien_free;
        alien->header.call = _uc_async_alien_call;
    }
    alien->refcount++;

    return &alien->header;
}

void 
async_alien_free( async_manager_t *manager, struct async_alien *alien )
{
    if( !alien )
        return;

    // The futex is locked, 
    async_manager_unlink( alien->manager );
    alien->manager = 0;

    if( 0 == alien->refcount )
    {
        uc_async_callback_queuer_free( &alien->header.queuer );
        free( alien );
        return;
    }
    
    // release it, there are still aliens around which will try to enter it.
    async_alien_release_futex( &alien->the_futex );
}

#else  // defined ASYNC_HAS_ALIENS

static const uc_async_alient_t *
_uc_async_new_alien( struct uc_async_manager * )
{
    return 0;
}

#endif // nded ASYNC_HAS_ALIENS

void 
async_alien_init( async_manager_t *manager, uc_value_t *scope )
{
    manager->header.new_alien = _uc_async_new_alien;
}

