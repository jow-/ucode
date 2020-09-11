/*
 * Copyright (C) 2020 Jo-Philipp Wich <jo@mein.io>
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

#include "../module.h"

#include <math.h>
#include <sys/time.h>

static const struct ut_ops *ops;

static double
to_double(struct json_object *v)
{
	int64_t n;
	double d;

	return (ops->cast_number(v, &n, &d) == json_type_double) ? d : (double)n;
}

static int64_t
to_int64(struct json_object *v)
{
	int64_t n;
	double d;

	return (ops->cast_number(v, &n, &d) == json_type_double) ? (int64_t)d : n;
}

static struct json_object *
ut_abs(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *v = json_object_array_get_idx(args, 0);
	enum json_type t;
	int64_t n;
	double d;

	if (json_object_is_type(v, json_type_null))
		return ops->new_double(NAN);

	t = ops->cast_number(v, &n, &d);

	if (t == json_type_double)
		return (isnan(d) || d < 0) ? ops->new_double(-d) : json_object_get(v);

	return (n < 0) ? json_object_new_int64(-n) : json_object_get(v);
}

static struct json_object *
ut_atan2(struct ut_state *s, uint32_t off, struct json_object *args)
{
	double d1 = to_double(json_object_array_get_idx(args, 0));
	double d2 = to_double(json_object_array_get_idx(args, 1));

	if (isnan(d1) || isnan(d2))
		return ops->new_double(NAN);

	return ops->new_double(atan2(d1, d2));
}

static struct json_object *
ut_cos(struct ut_state *s, uint32_t off, struct json_object *args)
{
	double d = to_double(json_object_array_get_idx(args, 0));

	if (isnan(d))
		return ops->new_double(NAN);

	return ops->new_double(cos(d));
}

static struct json_object *
ut_exp(struct ut_state *s, uint32_t off, struct json_object *args)
{
	double d = to_double(json_object_array_get_idx(args, 0));

	if (isnan(d))
		return ops->new_double(NAN);

	return ops->new_double(exp(d));
}

static struct json_object *
ut_log(struct ut_state *s, uint32_t off, struct json_object *args)
{
	double d = to_double(json_object_array_get_idx(args, 0));

	if (isnan(d))
		return ops->new_double(NAN);

	return ops->new_double(log(d));
}

static struct json_object *
ut_sin(struct ut_state *s, uint32_t off, struct json_object *args)
{
	double d = to_double(json_object_array_get_idx(args, 0));

	if (isnan(d))
		return ops->new_double(NAN);

	return ops->new_double(sin(d));
}

static struct json_object *
ut_sqrt(struct ut_state *s, uint32_t off, struct json_object *args)
{
	double d = to_double(json_object_array_get_idx(args, 0));

	if (isnan(d))
		return ops->new_double(NAN);

	return ops->new_double(sqrt(d));
}

static struct json_object *
ut_pow(struct ut_state *s, uint32_t off, struct json_object *args)
{
	double x = to_double(json_object_array_get_idx(args, 0));
	double y = to_double(json_object_array_get_idx(args, 1));

	if (isnan(x) || isnan(y))
		return ops->new_double(NAN);

	return ops->new_double(pow(x, y));
}

static struct json_object *
ut_rand(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct timeval tv;

	if (!s->srand_called) {
		gettimeofday(&tv, NULL);
		srand((tv.tv_sec * 1000) + (tv.tv_usec / 1000));

		s->srand_called = true;
	}

	return json_object_new_int64(rand());
}

static struct json_object *
ut_srand(struct ut_state *s, uint32_t off, struct json_object *args)
{

	int64_t n = to_int64(json_object_array_get_idx(args, 0));

	srand((unsigned int)n);
	s->srand_called = true;

	return NULL;
}

static const struct { const char *name; ut_c_fn *func; } global_fns[] = {
	{ "abs",		ut_abs },
	{ "atan2",		ut_atan2 },
	{ "cos",		ut_cos },
	{ "exp",		ut_exp },
	{ "log",		ut_log },
	{ "sin",		ut_sin },
	{ "sqrt",		ut_sqrt },
	{ "pow",		ut_pow },
	{ "rand",		ut_rand },
	{ "srand",		ut_srand },
};

void ut_module_init(const struct ut_ops *ut, struct ut_state *s, struct json_object *scope)
{
	ops = ut;

	register_functions(ops, global_fns, scope);
}
