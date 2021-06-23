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
} uc_cfunction_list;

extern const uc_cfunction_list uc_stdlib_functions[];

void uc_load_stdlib(uc_value_t *scope);
uc_value_t *uc_alloc_global(uc_vm *vm);

bool format_source_context(uc_stringbuf_t *buf, uc_source *src, size_t off, bool compact);
bool format_error_context(uc_stringbuf_t *buf, uc_source *src, uc_value_t *stacktrace, size_t off);


/* vm helper */

static inline void *
_uc_get_self(uc_vm *vm, const char *expected_type)
{
	return ucv_ressource_dataptr(vm->callframes.entries[vm->callframes.count - 1].ctx, expected_type);
}

#define uc_get_self(...) _uc_get_self(vm, __VA_ARGS__)

static inline uc_value_t *
_uc_get_arg(uc_vm *vm, size_t nargs, size_t n)
{
	if (n >= nargs)
		return NULL;

	return uc_vm_stack_peek(vm, nargs - n - 1);
}

#define uc_get_arg(...) _uc_get_arg(vm, nargs, __VA_ARGS__)

#define uc_call(nargs) uc_vm_call(vm, false, nargs)
#define uc_push_val(val) uc_vm_stack_push(vm, val)
#define uc_pop_val() uc_vm_stack_pop(vm)


/* value helper */

static inline uc_value_t *
uc_alloc_ressource(uc_ressource_type_t *type, void *data)
{
	return ucv_ressource_new(type, data);
}

static inline uc_type_t
uc_to_number(uc_value_t *v, int64_t *n, double *d)
{
	return uc_cast_number(v, n, d);
}

static inline double
uc_to_double(uc_value_t *v)
{
	int64_t n;
	double d;

	return (uc_cast_number(v, &n, &d) == UC_DOUBLE) ? d : (double)n;
}

static inline int64_t
uc_to_int64(uc_value_t *v)
{
	int64_t n;
	double d;

	return (uc_cast_number(v, &n, &d) == UC_DOUBLE) ? (int64_t)d : n;
}


/* ressource type helper */

static inline uc_ressource_type_t *
_uc_declare_type(uc_vm *vm, const char *name, const uc_cfunction_list *list, size_t len, void (*freefn)(void *))
{
	uc_value_t *proto = ucv_object_new(NULL);

	while (len-- > 0)
		ucv_object_add(proto, list[len].name,
			ucv_cfunction_new(list[len].name, list[len].func));

	return ucv_ressource_type_add(vm, name, proto, freefn);
}

#define uc_declare_type(vm, name, functions, freefn) \
	_uc_declare_type(vm, name, functions, ARRAY_SIZE(functions), freefn)


/* function helper */

#define uc_add_function(object, name, function) \
	ucv_object_add(object, name, ucv_cfunction_new(name, function))

static inline bool
_uc_add_functions(uc_value_t *object, const uc_cfunction_list *list, size_t len)
{
	bool rv = true;

	while (len-- > 0)
		rv &= uc_add_function(object, list[len].name, list[len].func);

	return rv;
}

#define uc_add_functions(object, functions) \
	_uc_add_functions(object, functions, ARRAY_SIZE(functions))

#endif /* __LIB_H_ */
