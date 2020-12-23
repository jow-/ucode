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
#include "object.h"

typedef struct {
	const char *name;
	uc_cfn_ptr func;
} uc_cfunction_list;

typedef struct {
	/* value operations */
	struct {
		uc_prototype *(*proto)(uc_prototype *);
		uc_cfunction *(*cfunc)(const char *, uc_cfn_ptr);
		json_object *(*dbl)(double);
		uc_regexp *(*regexp)(const char *, bool, bool, bool, char **);
		uc_ressource *(*ressource)(json_object *, uc_ressource_type *, void *);
		enum json_type (*tonumber)(json_object *, int64_t *, double *);
	} value;

	/* ressource operations */
	struct {
		uc_ressource_type *(*define)(const char *, uc_prototype *, void (*)(void *));
		uc_ressource *(*create)(json_object *, uc_ressource_type *, void *);
		void **(*data)(json_object *, const char *);
		uc_prototype *(*proto)(json_object *);
	} ressource;

	/* VM operations */
	struct {
		uc_exception_type_t (*call)(uc_vm *, bool, size_t);
		json_object *(*peek)(uc_vm *, size_t);
		json_object *(*pop)(uc_vm *);
		void (*push)(uc_vm *, json_object *);
		void (*raise)(uc_vm *, uc_exception_type_t, const char *, ...);
	} vm;
} uc_ops;

extern const uc_ops uc;

void uc_lib_init(uc_prototype *scope);

void format_source_context(char **msg, size_t *msglen, uc_source *src, size_t off, bool compact);
void format_error_context(char **msg, size_t *msglen, uc_source *src, json_object *stacktrace, size_t off);


/* vm helper */

static inline void *
_uc_get_self(const uc_ops *ops, uc_vm *vm, const char *expected_type)
{
	return ops->ressource.data(vm->callframes.entries[vm->callframes.count - 1].ctx, expected_type);
}

#define uc_get_self(...) _uc_get_self(ops, vm, __VA_ARGS__)

static inline json_object *
_uc_get_arg(const uc_ops *ops, uc_vm *vm, size_t nargs, size_t n)
{
	if (n >= nargs)
		return NULL;

	return ops->vm.peek(vm, nargs - n - 1);
}

#define uc_get_arg(...) _uc_get_arg(ops, vm, nargs, __VA_ARGS__)

#define uc_call(nargs) ops->vm.call(vm, false, nargs)
#define uc_push_val(val) ops->vm.push(vm, val)
#define uc_pop_val() ops->vm.pop(vm)


/* value helper */

static inline json_object *
_uc_alloc_proto(const uc_ops *ops, uc_prototype *parent)
{
	return ops->value.proto(parent)->header.jso;
}

static inline json_object *
_uc_alloc_cfunc(const uc_ops *ops, const char *name, uc_cfn_ptr fptr)
{
	return ops->value.cfunc(name, fptr)->header.jso;
}

static inline json_object *
_uc_alloc_double(const uc_ops *ops, double dbl)
{
	return ops->value.dbl(dbl);
}

static inline json_object *
_uc_alloc_regexp(const uc_ops *ops, const char *pattern, bool global, bool icase, bool newline, char **errp)
{
	uc_regexp *re = ops->value.regexp(pattern, global, icase, newline, errp);

	return re ? re->header.jso : NULL;
}

static inline json_object *
_uc_alloc_ressource(const uc_ops *ops, uc_ressource_type *type, void *data)
{
	uc_ressource *res = ops->value.ressource(xjs_new_object(), type, data);

	return res ? res->header.jso : NULL;
}

#define uc_alloc_proto(...) _uc_alloc_proto(ops, __VA_ARGS__)
#define uc_alloc_cfunc(...) _uc_alloc_cfunc(ops, __VA_ARGS__)
#define uc_alloc_double(...) _uc_alloc_double(ops, __VA_ARGS__)
#define uc_alloc_regexp(...) _uc_alloc_regexp(ops, __VA_ARGS__)
#define uc_alloc_ressource(...) _uc_alloc_ressource(ops, __VA_ARGS__)

static inline json_type
_uc_to_number(const uc_ops *ops, json_object *v, int64_t *n, double *d)
{
	return ops->value.tonumber(v, n, d);
}

static inline double
_uc_to_double(const uc_ops *ops, json_object *v)
{
	int64_t n;
	double d;

	return (ops->value.tonumber(v, &n, &d) == json_type_double) ? d : (double)n;
}

static inline int64_t
_uc_to_int64(const uc_ops *ops, json_object *v)
{
	int64_t n;
	double d;

	return (ops->value.tonumber(v, &n, &d) == json_type_double) ? (int64_t)d : n;
}

#define uc_to_number(...) _uc_to_number(ops, __VA_ARGS__)
#define uc_to_double(...) _uc_to_double(ops, __VA_ARGS__)
#define uc_to_int64(...) _uc_to_int64(ops, __VA_ARGS__)


/* ressource type helper */

static inline uc_ressource_type *
_uc_declare_type(const uc_ops *ops, const char *name, const uc_cfunction_list *list, size_t len, void (*freefn)(void *))
{
	uc_prototype *proto = ops->value.proto(NULL);

	while (len-- > 0)
		json_object_object_add(proto->header.jso, list[len].name,
			_uc_alloc_cfunc(ops, list[len].name, list[len].func));

	return ops->ressource.define(name, proto, freefn);
}

#define uc_declare_type(name, functions, freefn) \
	_uc_declare_type(ops, name, functions, ARRAY_SIZE(functions), freefn)


/* prototype helper */

static inline bool
uc_add_proto_val(uc_prototype *proto, const char *key, json_object *value)
{
	if (!proto)
		return false;

	return json_object_object_add(proto->header.jso, key, value);
}

static inline void
_uc_add_proto_functions(const uc_ops *ops, uc_prototype *proto, const uc_cfunction_list *list, size_t len)
{
	while (len-- > 0)
		json_object_object_add(proto->header.jso, list[len].name,
			_uc_alloc_cfunc(ops, list[len].name, list[len].func));
}

#define uc_add_proto_functions(proto, functions) \
	_uc_add_proto_functions(ops, proto, functions, ARRAY_SIZE(functions))

#endif /* __LIB_H_ */
