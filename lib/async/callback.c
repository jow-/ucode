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
#include "ucode/async.h"

#include "manager.h"
#include "callback.h"


void
async_callback_destroy( uc_vm_t *vm, struct async_callback *pcb)
{
	switch ((async_callback_type_t)pcb->callback_type)
	{
	case callbackNone:
		break;
	case callbackUcode:
		if (pcb->ucode.func)
			ucv_put(pcb->ucode.func);
		pcb->ucode.func = 0;
		if (pcb->ucode.this)
			ucv_put(pcb->ucode.this);
		pcb->ucode.this = 0;
		break;
	case callbackC_int_user_flags:
		if (pcb->c_int_user_flags.func)
		{
			(*pcb->c_int_user_flags.func)( vm, pcb->c_int_user_flags.user, UC_ASYNC_CALLBACK_FLAG_CLEANUP);
			pcb->c_int_user_flags.func = 0;
			pcb->c_int_user_flags.user = 0;
		}
		break;
	case callbackC_int_user_args_flags:
		if (pcb->c_int_user_args_flags.func)
		{
			(*pcb->c_int_user_args_flags.func)( vm, pcb->c_int_user_args_flags.user, 0, 0, UC_ASYNC_CALLBACK_FLAG_CLEANUP);
			pcb->c_int_user_args_flags.func = 0;
			pcb->c_int_user_args_flags.user = 0;
		}
		break;
	}
	for (size_t n = 0; n < pcb->nargs; n++)
	{
		ucv_put(pcb->args[n]);
		pcb->args[n] = 0;
	}
	pcb->nargs = 0;
}

uc_value_t *
async_callback_get_ucode_func( async_manager_t *manager, struct async_callback *cb )
{
	switch ((async_callback_type_t)cb->callback_type)
	{
	case callbackNone:
		return 0;
	case callbackUcode:
		return ucv_get(cb->ucode.func);
	case callbackC_int_user_flags:
		return 0;
	case callbackC_int_user_args_flags:
		return 0;
	}
	return 0;
}

int
async_callback_call( async_manager_t *manager, struct async_callback *cb, uc_value_t **args, size_t nargs, uc_value_t **ret, bool cleanup)
{
	int flags = UC_ASYNC_CALLBACK_FLAG_EXECUTE | (cleanup ? UC_ASYNC_CALLBACK_FLAG_CLEANUP : 0);
	switch ((async_callback_type_t)cb->callback_type)
	{
	case callbackNone:
		return EXCEPTION_NONE;
	case callbackUcode:
	{
		uc_vm_t *vm = manager->vm;
		uc_vm_stack_push(vm, ucv_get(cb->ucode.func));
		for (size_t n = 0; n < nargs; n++)
			uc_vm_stack_push(vm, ucv_get(args[n]));
		for (size_t n = 0; n < cb->nargs; n++)
			uc_vm_stack_push(vm, ucv_get(cb->args[n]));
		int ex = uc_vm_call(vm, false, cb->nargs + nargs);
		if (cleanup)
		{
			ucv_put(cb->ucode.func);
			cb->ucode.func = 0;
			ucv_put(cb->ucode.this);
			cb->ucode.this = 0;
			for (size_t n = 0; n < cb->nargs; n++)
			{
				ucv_put(cb->args[n]);
				cb->args[n] = 0;
			}
			cb->nargs = 0;
		}
		if (ex != EXCEPTION_NONE)
			return ex;
		uc_value_t *pret = uc_vm_stack_pop(vm);
		if (ret)
			*ret = pret;
		else
			ucv_put(pret);
		return ex;
	}
	case callbackC_int_user_flags:
	{
		if (!cb->c_int_user_flags.func)
			return EXCEPTION_NONE;
		int ex = (*cb->c_int_user_flags.func)(manager->vm, cb->c_int_user_flags.user, flags);
		if (cleanup)
		{
			cb->c_int_user_flags.func = 0;
			cb->c_int_user_flags.user = 0;
		}
		return ex;
	}
	case callbackC_int_user_args_flags:
	{
		if (!cb->c_int_user_flags.func)
			return EXCEPTION_NONE;
		uc_value_t *args2[nargs + cb->nargs];
		size_t m = 0;
		for (size_t n = 0; n < nargs; n++)
			args2[m++] = args[n];
		for (size_t n = 0; n < cb->nargs; n++)
			args2[m++] = cb->args[n];
		int ex = (*cb->c_int_user_args_flags.func)(manager->vm, cb->c_int_user_args_flags.user, args2, m, flags);
		if (cleanup)
		{
			cb->c_int_user_args_flags.func = 0;
			cb->c_int_user_args_flags.user = 0;
		}
		return ex;
	}
	}
	return EXCEPTION_NONE;
}
