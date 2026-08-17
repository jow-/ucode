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

#ifndef UC_ASYNC_CALLBACK_H
#define UC_ASYNC_CALLBACK_H

typedef enum
{
	callbackNone = 0,
	callbackUcode,
	callbackC_int_user_flags,
	callbackC_int_user_args_flags
} async_callback_type_t;

struct async_callback
{
	uint32_t callback_type : 4;
	uint32_t type : 4;
	uint32_t nargs : 8;
	uint32_t still_available_bits : 16;

	union
	{
		struct
		{
			uc_value_t *func;
			uc_value_t *this; // not used, so far
		} ucode;
		struct
		{
			int (*func)(uc_vm_t *, void *user, int flags);
			void *user;
		} c_int_user_flags;
		struct
		{
			int (*func)(uc_vm_t *, void *user, uc_value_t **args, size_t nargs, int flags);
			void *user;
		} c_int_user_args_flags;
	};

	uc_value_t *args[];
};

extern __hidden uc_value_t *
async_callback_get_ucode_func( async_manager_t *manager, struct async_callback *cb );

extern __hidden void
async_callback_destroy( uc_vm_t *vm, struct async_callback *pcb);

extern __hidden int
async_callback_call( async_manager_t *manager, struct async_callback *cb, uc_value_t **args, size_t nargs, uc_value_t **ret, bool cleanup);

#endif //ndef UC_ASYNC_CALLBACK_H
