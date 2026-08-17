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
#ifndef UC_ASYNC_ALIEN_H
#define UC_ASYNC_ALIEN_H

#include "manager.h"

#ifdef ASYNC_HAS_ALIENS
extern __hidden void
async_alien_enter( async_manager_t *manager );

extern __hidden void
async_alien_release( async_manager_t *manager );

typedef struct async_alien
{
    uc_async_alient_t header;

    // Counter which is incremented at each todo added,
    // to know if an alien call should interrupt the sleep
    int todo_seq;
	
	_Atomic uint32_t the_futex;
    uint32_t refcount;

    // zero if vm ended
    async_manager_t *manager;

    uc_thread_context_t *thread_context;
} async_alien_t;

extern __hidden void 
async_alien_free( async_manager_t *, struct async_alien * );

#   define ASYNC_ALIEN_ENTER(manager) async_alien_enter( manager )
#   define ASYNC_ALIEN_LEAVE(manager) async_alien_release( manager )
#   define ASYNC_ALIEN_TODO_INCREMENT(manager) if( manager->alien ) manager->alien->todo_seq++
#   define IF_NO_MORE_ALIENS(manager) \
    if( 0 == manager->alien || 0 == manager->alien->refcount ) // no more aliens
                 

#else // ASYNC_HAS_ALIENS

#   define ASYNC_ALIEN_ENTER(...) do{}while(0)
#   define ASYNC_ALIEN_LEAVE(...) do{}while(0)
#   define ASYNC_ALIEN_TODO_INCREMENT(...) do{}while(0)
#   define IF_NO_MORE_ALIENS(...)
#endif // 

extern __hidden void 
async_alien_init( async_manager_t *manager, uc_value_t *scope );

#endif //ndef UC_ASYNC_ALIEN_H

