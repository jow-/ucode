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

#include <math.h>
#include <sys/time.h>

#include "../module.h"

static bool srand_called = false;

static json_object *
uc_abs(uc_vm *vm, size_t nargs)
{
	json_object *v = uc_get_arg(0);
	enum json_type t;
	int64_t n;
	double d;

	if (json_object_is_type(v, json_type_null))
		return uc_alloc_double(NAN);

	t = uc_to_number(v, &n, &d);

	if (t == json_type_double)
		return (isnan(d) || d < 0) ? uc_alloc_double(-d) : json_object_get(v);

	return (n < 0) ? json_object_new_int64(-n) : json_object_get(v);
}

static json_object *
uc_atan2(uc_vm *vm, size_t nargs)
{
	double d1 = uc_to_double(uc_get_arg(0));
	double d2 = uc_to_double(uc_get_arg(1));

	if (isnan(d1) || isnan(d2))
		return uc_alloc_double(NAN);

	return uc_alloc_double(atan2(d1, d2));
}

static json_object *
uc_cos(uc_vm *vm, size_t nargs)
{
	double d = uc_to_double(uc_get_arg(0));

	if (isnan(d))
		return uc_alloc_double(NAN);

	return uc_alloc_double(cos(d));
}

static json_object *
uc_exp(uc_vm *vm, size_t nargs)
{
	double d = uc_to_double(uc_get_arg(0));

	if (isnan(d))
		return uc_alloc_double(NAN);

	return uc_alloc_double(exp(d));
}

static json_object *
uc_log(uc_vm *vm, size_t nargs)
{
	double d = uc_to_double(uc_get_arg(0));

	if (isnan(d))
		return uc_alloc_double(NAN);

	return uc_alloc_double(log(d));
}

static json_object *
uc_sin(uc_vm *vm, size_t nargs)
{
	double d = uc_to_double(uc_get_arg(0));

	if (isnan(d))
		return uc_alloc_double(NAN);

	return uc_alloc_double(sin(d));
}

static json_object *
uc_sqrt(uc_vm *vm, size_t nargs)
{
	double d = uc_to_double(uc_get_arg(0));

	if (isnan(d))
		return uc_alloc_double(NAN);

	return uc_alloc_double(sqrt(d));
}

static json_object *
uc_pow(uc_vm *vm, size_t nargs)
{
	double x = uc_to_double(uc_get_arg(0));
	double y = uc_to_double(uc_get_arg(1));

	if (isnan(x) || isnan(y))
		return uc_alloc_double(NAN);

	return uc_alloc_double(pow(x, y));
}

static json_object *
uc_rand(uc_vm *vm, size_t nargs)
{
	struct timeval tv;

	if (!srand_called) {
		gettimeofday(&tv, NULL);
		srand((tv.tv_sec * 1000) + (tv.tv_usec / 1000));

		srand_called = true;
	}

	return json_object_new_int64(rand());
}

static json_object *
uc_srand(uc_vm *vm, size_t nargs)
{
	int64_t n = uc_to_int64(uc_get_arg(0));

	srand((unsigned int)n);
	srand_called = true;

	return NULL;
}

static const uc_cfunction_list math_fns[] = {
	{ "abs",	uc_abs },
	{ "atan2",	uc_atan2 },
	{ "cos",	uc_cos },
	{ "exp",	uc_exp },
	{ "log",	uc_log },
	{ "sin",	uc_sin },
	{ "sqrt",	uc_sqrt },
	{ "pow",	uc_pow },
	{ "rand",	uc_rand },
	{ "srand",	uc_srand },
};

void uc_module_init(uc_prototype *scope)
{
	uc_add_proto_functions(scope, math_fns);
}
