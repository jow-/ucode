/*
 * Copyright (C) 2020-2021 Jo-Philipp Wich <jo@mein.io>
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

#ifndef __LIB_H_
#define __LIB_H_

#include "vm.h"
#include "lexer.h"


typedef struct {
	const char *name;
	uc_cfn_ptr_t func;
} uc_function_list_t;

extern const uc_function_list_t uc_stdlib_functions[];

void uc_stdlib_load(uc_value_t *scope);

bool uc_source_context_format(uc_stringbuf_t *buf, uc_source_t *src, size_t off, bool compact);
bool uc_error_context_format(uc_stringbuf_t *buf, uc_source_t *src, uc_value_t *stacktrace, size_t off);


/* vm helper */

static inline void *
_uc_fn_this(uc_vm_t *vm, const char *expected_type)
{
	return ucv_ressource_dataptr(vm->callframes.entries[vm->callframes.count - 1].ctx, expected_type);
}

#define uc_fn_this(...) _uc_fn_this(vm, __VA_ARGS__)

static inline uc_value_t *
_uc_fn_arg(uc_vm_t *vm, size_t nargs, size_t n)
{
	if (n >= nargs)
		return NULL;

	return uc_vm_stack_peek(vm, nargs - n - 1);
}

#define uc_fn_arg(...) _uc_fn_arg(vm, nargs, __VA_ARGS__)

#define uc_call(nargs) uc_vm_call(vm, false, nargs)
#define uc_value_push(val) uc_vm_stack_push(vm, val)
#define uc_value_pop() uc_vm_stack_pop(vm)


/* ressource type helper */

static inline uc_value_t *
uc_ressource_new(uc_ressource_type_t *type, void *data)
{
	return ucv_ressource_new(type, data);
}

static inline uc_ressource_type_t *
_uc_type_declare(uc_vm_t *vm, const char *name, const uc_function_list_t *list, size_t len, void (*freefn)(void *))
{
	uc_value_t *proto = ucv_object_new(NULL);

	while (len-- > 0)
		ucv_object_add(proto, list[len].name,
			ucv_cfunction_new(list[len].name, list[len].func));

	return ucv_ressource_type_add(vm, name, proto, freefn);
}

#define uc_type_declare(vm, name, functions, freefn) \
	_uc_type_declare(vm, name, functions, ARRAY_SIZE(functions), freefn)


/* function helper */

#define uc_function_register(object, name, function) \
	ucv_object_add(object, name, ucv_cfunction_new(name, function))

static inline bool
_uc_function_list_register(uc_value_t *object, const uc_function_list_t *list, size_t len)
{
	bool rv = true;

	while (len-- > 0)
		rv &= uc_function_register(object, list[len].name, list[len].func);

	return rv;
}

#define uc_function_list_register(object, functions) \
	_uc_function_list_register(object, functions, ARRAY_SIZE(functions))

#endif /* __LIB_H_ */
