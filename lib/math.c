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
#include <errno.h>
#include <sys/time.h>

#include "ucode/module.h"

static bool srand_called = false;

static uc_value_t *
uc_abs(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *v = uc_fn_arg(0), *nv, *res;
	int64_t n;
	double d;

	nv = v ? ucv_to_number(v) : NULL;

	switch (ucv_type(nv)) {
	case UC_INTEGER:
		n = ucv_int64_get(nv);

		if (n >= 0 || errno == ERANGE)
			res = ucv_get(nv);
		else if (n == INT64_MIN)
			res = ucv_uint64_new((uint64_t)INT64_MAX + 1);
		else
			res = ucv_uint64_new(-n);

		break;

	case UC_DOUBLE:
		d = ucv_double_get(nv);

		if (isnan(d) || d >= 0)
			res = ucv_get(nv);
		else
			res = ucv_double_new(-d);

		break;

	default:
		res = ucv_double_new(NAN);
		break;
	}

	ucv_put(nv);

	return res;
}

static uc_value_t *
uc_atan2(uc_vm_t *vm, size_t nargs)
{
	double d1 = ucv_to_double(uc_fn_arg(0));
	double d2 = ucv_to_double(uc_fn_arg(1));

	if (isnan(d1) || isnan(d2))
		return ucv_double_new(NAN);

	return ucv_double_new(atan2(d1, d2));
}

static uc_value_t *
uc_cos(uc_vm_t *vm, size_t nargs)
{
	double d = ucv_to_double(uc_fn_arg(0));

	if (isnan(d))
		return ucv_double_new(NAN);

	return ucv_double_new(cos(d));
}

static uc_value_t *
uc_exp(uc_vm_t *vm, size_t nargs)
{
	double d = ucv_to_double(uc_fn_arg(0));

	if (isnan(d))
		return ucv_double_new(NAN);

	return ucv_double_new(exp(d));
}

static uc_value_t *
uc_log(uc_vm_t *vm, size_t nargs)
{
	double d = ucv_to_double(uc_fn_arg(0));

	if (isnan(d))
		return ucv_double_new(NAN);

	return ucv_double_new(log(d));
}

static uc_value_t *
uc_sin(uc_vm_t *vm, size_t nargs)
{
	double d = ucv_to_double(uc_fn_arg(0));

	if (isnan(d))
		return ucv_double_new(NAN);

	return ucv_double_new(sin(d));
}

static uc_value_t *
uc_sqrt(uc_vm_t *vm, size_t nargs)
{
	double d = ucv_to_double(uc_fn_arg(0));

	if (isnan(d))
		return ucv_double_new(NAN);

	return ucv_double_new(sqrt(d));
}

static uc_value_t *
uc_pow(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));
	double y = ucv_to_double(uc_fn_arg(1));

	if (isnan(x) || isnan(y))
		return ucv_double_new(NAN);

	return ucv_double_new(pow(x, y));
}

static uc_value_t *
uc_rand(uc_vm_t *vm, size_t nargs)
{
	struct timeval tv;

	if (!srand_called) {
		gettimeofday(&tv, NULL);
		srand((tv.tv_sec * 1000) + (tv.tv_usec / 1000));

		srand_called = true;
	}

	return ucv_int64_new(rand());
}

static uc_value_t *
uc_srand(uc_vm_t *vm, size_t nargs)
{
	int64_t n = ucv_to_integer(uc_fn_arg(0));

	srand((unsigned int)n);
	srand_called = true;

	return NULL;
}

static const uc_function_list_t math_fns[] = {
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

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, math_fns);
}
