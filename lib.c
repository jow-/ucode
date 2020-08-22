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

#include "ast.h"
#include "parser.h"
#include "lexer.h"
#include "eval.h"
#include "lib.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>


static double
ut_cast_double(struct json_object *v)
{
	enum json_type t;
	int64_t n;
	double d;

	t = ut_cast_number(v, &n, &d);
	errno = 0;

	if (t == json_type_double) {
		if (isnan(d))
			errno = EINVAL;
		else if (!isfinite(d))
			errno = EOVERFLOW;

		return d;
	}

	return (double)n;
}

static int64_t
ut_cast_int64(struct json_object *v)
{
	enum json_type t;
	int64_t n;
	double d;

	t = ut_cast_number(v, &n, &d);
	errno = 0;

	if (t == json_type_double) {
		if (isnan(d))
			errno = EINVAL;
		else if (!isfinite(d))
			errno = EOVERFLOW;
		else if (ceil(d) != d)
			errno = ERANGE;

		return (int64_t)d;
	}

	return n;
}

static struct json_object *
ut_print(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *item;
	size_t arridx, arrlen;
	size_t reslen = 0;
	size_t len = 0;
	const char *p;

	for (arridx = 0, arrlen = json_object_array_length(args);
	     arridx < arrlen; arridx++) {
		item = json_object_array_get_idx(args, arridx);

		if (json_object_is_type(item, json_type_string)) {
			p = json_object_get_string(item);
			len = json_object_get_string_len(item);
		}
		else {
			p = item ? json_object_get_string(item) : NULL;
			p = p ? p : "";
			len = strlen(p);
		}

		reslen += fwrite(p, 1, len, stdout);
	}

	return json_object_new_int64(reslen);
}

static struct json_object *
ut_length(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *arg = json_object_array_get_idx(args, 0);

	switch (json_object_get_type(arg)) {
	case json_type_array:
		return json_object_new_int64(json_object_array_length(arg));

	case json_type_string:
		return json_object_new_int64(json_object_get_string_len(arg));

	default:
		return NULL;
	}
}

static struct json_object *
ut_index(struct ut_state *s, struct ut_opcode *op, struct json_object *args, bool right)
{
	struct json_object *stack = json_object_array_get_idx(args, 0);
	struct json_object *needle = json_object_array_get_idx(args, 1);
	size_t arridx, len, ret = -1;
	const char *sstr, *nstr, *p;

	switch (json_object_get_type(stack)) {
	case json_type_array:
		for (arridx = 0, len = json_object_array_length(stack); arridx < len; arridx++) {
			if (ut_cmp(T_EQ, json_object_array_get_idx(stack, arridx), needle)) {
				ret = arridx;

				if (!right)
					break;
			}
		}

		return json_object_new_int64(ret);

	case json_type_string:
		sstr = json_object_get_string(stack);
		nstr = needle ? json_object_get_string(needle) : NULL;
		len = needle ? strlen(nstr) : 0;

		for (p = sstr; *p && len; p++) {
			if (!strncmp(p, nstr, len)) {
				ret = p - sstr;

				if (!right)
					break;
			}
		}

		return json_object_new_int64(ret);

	default:
		return NULL;
	}
}

static struct json_object *
ut_lindex(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	return ut_index(s, op, args, false);
}

static struct json_object *
ut_rindex(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	return ut_index(s, op, args, true);
}

static struct json_object *
ut_push(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *arr = json_object_array_get_idx(args, 0);
	struct json_object *item = NULL;
	size_t arridx, arrlen;

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	for (arridx = 1, arrlen = json_object_array_length(args);
	     arridx < arrlen; arridx++) {
		item = json_object_array_get_idx(args, arridx);
		json_object_array_add(arr, json_object_get(item));
	}

	return item;
}

static struct json_object *
ut_pop(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *arr = json_object_array_get_idx(args, 0);
	struct json_object *item = NULL;
	size_t arrlen;

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	arrlen = json_object_array_length(arr);

	if (arrlen > 0) {
		item = json_object_array_get_idx(arr, arrlen - 1);
		json_object_array_del_idx(arr, arrlen - 1, 1);
		json_object_array_shrink(arr, 0);
	}

	return json_object_get(item);
}

static struct json_object *
ut_shift(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *arr = json_object_array_get_idx(args, 0);
	struct json_object *item = NULL;
	size_t arridx, arrlen;

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	item = json_object_get(json_object_array_get_idx(arr, 0));
	arrlen = json_object_array_length(arr);

	for (arridx = 0; arridx < arrlen - 1; arridx++)
		json_object_array_put_idx(arr, arridx,
			json_object_array_get_idx(arr, arridx + 1));

	json_object_array_del_idx(arr, arrlen - 1, 1);
	json_object_array_shrink(arr, 0);

	return item;
}

static struct json_object *
ut_unshift(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *arr = json_object_array_get_idx(args, 0);
	struct json_object *item = NULL;
	size_t arridx, arrlen, addlen;

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	arrlen = json_object_array_length(arr);
	addlen = json_object_array_length(args) - 1;

	for (arridx = arrlen; arridx > 0; arridx--)
		json_object_array_put_idx(arr, arridx + addlen - 1,
			json_object_get(json_object_array_get_idx(arr, arridx - 1)));

	for (arridx = 0; arridx < addlen; arridx++) {
		item = json_object_array_get_idx(args, arridx + 1);
		json_object_array_put_idx(arr, arridx, json_object_get(item));
	}

	return item;
}

static struct json_object *
ut_abs(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *v = json_object_array_get_idx(args, 0);
	enum json_type t;
	int64_t n;
	double d;

	if (json_object_is_type(v, json_type_null))
		return json_object_new_double_rounded(NAN);

	t = ut_cast_number(v, &n, &d);

	if (t == json_type_double)
		return (isnan(d) || d < 0) ? json_object_new_double_rounded(-d) : json_object_get(v);

	return (n < 0) ? json_object_new_int64(-n) : json_object_get(v);
}

static struct json_object *
ut_atan2(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	double d1 = ut_cast_double(json_object_array_get_idx(args, 0));
	double d2 = ut_cast_double(json_object_array_get_idx(args, 1));

	if (isnan(d1) || isnan(d2))
		return json_object_new_double_rounded(NAN);

	return json_object_new_double_rounded(atan2(d1, d2));
}

static struct json_object *
ut_chr(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	size_t len = json_object_array_length(args);
	size_t idx;
	int64_t n;
	char *str;

	if (!len)
		return json_object_new_string_len("", 0);

	str = calloc(1, len);

	if (!str)
		return ut_exception(s, op, UT_ERRMSG_OOM);

	for (idx = 0; idx < len; idx++) {
		n = ut_cast_int64(json_object_array_get_idx(args, idx));

		if (n < 0)
			n = 0;
		else if (n > 255)
			n = 255;

		str[idx] = (char)n;
	}

	return json_object_new_string_len(str, len);
}

static struct json_object *
ut_cos(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	double d = ut_cast_double(json_object_array_get_idx(args, 0));

	if (isnan(d))
		return json_object_new_double_rounded(NAN);

	return json_object_new_double_rounded(cos(d));
}

static struct json_object *
ut_delete(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *obj = json_object_array_get_idx(args, 0);
	struct json_object *rv = NULL;
	size_t arridx, arrlen;
	const char *key;

	if (!json_object_is_type(obj, json_type_object))
		return NULL;

	for (arrlen = json_object_array_length(args), arridx = 1; arridx < arrlen; arridx++) {
		ut_putval(rv);

		key = json_object_get_string(json_object_array_get_idx(args, arridx));
		rv = json_object_get(json_object_object_get(obj, key ? key : "null"));

		json_object_object_del(obj, key ? key : "null");
	}

	return rv;
}

static struct json_object *
ut_die(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	const char *msg = json_object_get_string(json_object_array_get_idx(args, 0));

	return ut_exception(s, op, "%s", msg ? msg : "Died");
}

static struct json_object *
ut_exists(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *obj = json_object_array_get_idx(args, 0);
	const char *key = json_object_get_string(json_object_array_get_idx(args, 1));

	if (!json_object_is_type(obj, json_type_object))
		return false;

	return json_object_new_boolean(json_object_object_get_ex(obj, key ? key : "null", NULL));
}

__attribute__((noreturn)) static struct json_object *
ut_exit(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	int64_t n = ut_cast_int64(json_object_array_get_idx(args, 0));

	exit(n);
}

static struct json_object *
ut_exp(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	double d = ut_cast_double(json_object_array_get_idx(args, 0));

	if (isnan(d))
		return json_object_new_double_rounded(NAN);

	return json_object_new_double_rounded(exp(d));
}

static struct json_object *
ut_getenv(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	const char *key = json_object_get_string(json_object_array_get_idx(args, 0));
	char *val = key ? getenv(key) : NULL;

	return val ? json_object_new_string(val) : NULL;
}

static struct json_object *
ut_filter(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *obj = json_object_array_get_idx(args, 0);
	struct json_object *func = json_object_array_get_idx(args, 1);
	struct json_object *rv, *arr, *cmpargs;
	size_t arridx, arrlen;

	if (!json_object_is_type(obj, json_type_array))
		return NULL;

	arr = json_object_new_array();
	cmpargs = json_object_new_array();

	if (!arr || !cmpargs) {
		ut_putval(arr);
		ut_putval(cmpargs);

		return ut_exception(s, op, UT_ERRMSG_OOM);
	}

	json_object_array_put_idx(cmpargs, 2, json_object_get(obj));

	for (arrlen = json_object_array_length(obj), arridx = 0; arridx < arrlen; arridx++) {
		json_object_array_put_idx(cmpargs, 0, json_object_get(json_object_array_get_idx(obj, arridx)));
		json_object_array_put_idx(cmpargs, 1, json_object_new_int64(arridx));

		rv = ut_invoke(s, op, func, cmpargs);

		if (ut_val_is_truish(rv))
			json_object_array_add(arr, json_object_get(json_object_array_get_idx(obj, arridx)));

		ut_putval(rv);
	}

	ut_putval(cmpargs);

	return arr;
}

static struct json_object *
ut_hex(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	const char *val = json_object_get_string(json_object_array_get_idx(args, 0));
	int64_t n;
	char *e;

	if (!val || !isxdigit(*val))
		return json_object_new_double_rounded(NAN);

	n = strtoll(val, &e, 16);

	if (e == val || *e)
		return json_object_new_double_rounded(NAN);

	return json_object_new_int64(n);
}

static struct json_object *
ut_int(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	int64_t n = ut_cast_int64(json_object_array_get_idx(args, 0));

	if (errno == EINVAL || errno == EOVERFLOW)
		return json_object_new_double_rounded(NAN);

	return json_object_new_int64(n);
}

static struct json_object *
ut_join(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	const char *sep = json_object_get_string(json_object_array_get_idx(args, 0));
	struct json_object *arr = json_object_array_get_idx(args, 1);
	struct json_object *rv = NULL;
	size_t arrlen, arridx, len = 1;
	const char *item;
	char *res, *p;
	int ret;

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	for (arrlen = json_object_array_length(arr), arridx = 0; arridx < arrlen; arridx++) {
		if (arridx > 0)
			len += strlen(sep);

		item = json_object_get_string(json_object_array_get_idx(arr, arridx));
		len += item ? strlen(item) : 0;
	}

	p = res = calloc(1, len);

	if (!res)
		return ut_exception(s, op, UT_ERRMSG_OOM);

	for (arrlen = json_object_array_length(arr), arridx = 0; arridx < arrlen; arridx++) {
		if (arridx > 0) {
			ret = snprintf(p, len, "%s", sep);

			if (ret < 0 || ret >= len)
				goto out;

			len -= ret;
			p += ret;
		}

		item = json_object_get_string(json_object_array_get_idx(arr, arridx));

		if (item) {
			ret = snprintf(p, len, "%s", item);

			if (ret < 0 || ret >= len)
				goto out;

			len -= ret;
			p += ret;
		}
	}

	rv = json_object_new_string(res);

out:
	free(res);

	return rv;
}

static struct json_object *
ut_keys(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *obj = json_object_array_get_idx(args, 0);
	struct json_object *arr = NULL;

	if (!json_object_is_type(obj, json_type_object))
		return NULL;

	arr = json_object_new_array();

	if (!arr)
		return ut_exception(s, op, UT_ERRMSG_OOM);

	json_object_object_foreach(obj, key, val)
		json_object_array_add(arr, json_object_new_string(key));

	return arr;
}

static struct json_object *
ut_lc(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	const char *str = json_object_get_string(json_object_array_get_idx(args, 0));
	size_t len = str ? strlen(str) : 0;
	struct json_object *rv = NULL;
	char *res, *p;

	if (!str)
		return NULL;

	res = p = calloc(1, len);

	if (!res)
		return ut_exception(s, op, UT_ERRMSG_OOM);

	while (*str)
		if (*str >= 'A' && *str <= 'Z')
			*p++ = 32 + *str++;
		else
			*p++ = *str++;

	rv = json_object_new_string_len(res, len);
	free(res);

	return rv;
}

static struct json_object *
ut_log(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	double d = ut_cast_double(json_object_array_get_idx(args, 0));

	if (isnan(d))
		return json_object_new_double_rounded(NAN);

	return json_object_new_double_rounded(log(d));
}

static struct json_object *
ut_map(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *obj = json_object_array_get_idx(args, 0);
	struct json_object *func = json_object_array_get_idx(args, 1);
	struct json_object *arr, *cmpargs;
	size_t arridx, arrlen;

	if (!json_object_is_type(obj, json_type_array))
		return NULL;

	arr = json_object_new_array();
	cmpargs = json_object_new_array();

	if (!arr || !cmpargs) {
		ut_putval(arr);
		ut_putval(cmpargs);

		return ut_exception(s, op, UT_ERRMSG_OOM);
	}

	json_object_array_put_idx(cmpargs, 2, json_object_get(obj));

	for (arrlen = json_object_array_length(obj), arridx = 0; arridx < arrlen; arridx++) {
		json_object_array_put_idx(cmpargs, 0, json_object_get(json_object_array_get_idx(obj, arridx)));
		json_object_array_put_idx(cmpargs, 1, json_object_new_int64(arridx));

		json_object_array_add(arr, ut_invoke(s, op, func, cmpargs));
	}

	ut_putval(cmpargs);

	return arr;
}

static struct json_object *
ut_ord(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *obj = json_object_array_get_idx(args, 0);
	const char *str;

	if (!json_object_is_type(obj, json_type_string))
		return NULL;

	str = json_object_get_string(obj);

	if (!str[0])
		return NULL;

	return json_object_new_int64((int64_t)str[0]);
}

static struct json_object *
ut_rand(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
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
ut_srand(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	int64_t n = ut_cast_int64(json_object_array_get_idx(args, 0));

	srand((unsigned int)n);
	s->srand_called = true;

	return NULL;
}

static struct json_object *
ut_type(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *v = json_object_array_get_idx(args, 0);
	struct ut_opcode *tag = json_object_get_userdata(v);

	switch (tag ? tag->type : 0) {
	case T_FUNC:
		return json_object_new_string("function");

	default:
		switch (json_object_get_type(v)) {
		case json_type_object:
			return json_object_new_string("object");

		case json_type_array:
			return json_object_new_string("array");

		case json_type_double:
			return json_object_new_string("double");

		case json_type_int:
			return json_object_new_string("int");

		case json_type_boolean:
			return json_object_new_string("bool");

		case json_type_string:
			return json_object_new_string("string");

		default:
			return NULL;
		}
	}
}

static struct json_object *
ut_reverse(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *obj = json_object_array_get_idx(args, 0);
	struct json_object *rv = NULL;
	size_t len, arridx;
	const char *str;
	char *dup, *p;

	if (json_object_is_type(obj, json_type_array)) {
		rv = json_object_new_array();

		if (!rv)
			return ut_exception(s, op, UT_ERRMSG_OOM);

		for (arridx = json_object_array_length(obj); arridx > 0; arridx--)
			json_object_array_add(rv, json_object_get(json_object_array_get_idx(obj, arridx - 1)));
	}
	else if (json_object_is_type(obj, json_type_string)) {
		len = json_object_get_string_len(obj);
		str = json_object_get_string(obj);
		p = dup = calloc(1, len + 1);

		if (!dup)
			return ut_exception(s, op, UT_ERRMSG_OOM);

		while (len > 0)
			*p++ = str[--len];

		rv = json_object_new_string(dup);

		free(dup);
	}

	return rv;
}

static struct json_object *
ut_sin(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	double d = ut_cast_double(json_object_array_get_idx(args, 0));

	if (isnan(d))
		return json_object_new_double_rounded(NAN);

	return json_object_new_double_rounded(sin(d));
}


static struct {
	struct ut_state *s;
	struct ut_opcode *op;
	struct json_object *fn;
	struct json_object *args;
} sort_ctx;

static int
sort_fn(const void *k1, const void *k2)
{
	struct json_object * const *v1 = k1;
	struct json_object * const *v2 = k2;
	struct json_object *rv;
	int ret;

	if (!sort_ctx.fn)
		return !ut_cmp(T_LT, *v1, *v2);

	json_object_array_put_idx(sort_ctx.args, 0, *v1);
	json_object_array_put_idx(sort_ctx.args, 1, *v2);

	rv = ut_invoke(sort_ctx.s, sort_ctx.op, sort_ctx.fn, sort_ctx.args);
	ret = !ut_val_is_truish(rv);

	ut_putval(rv);

	return ret;
}

static struct json_object *
ut_sort(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *arr = json_object_array_get_idx(args, 0);
	struct json_object *fn = json_object_array_get_idx(args, 1);

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	if (fn) {
		sort_ctx.s = s;
		sort_ctx.op = op;
		sort_ctx.fn = fn;
		sort_ctx.args = json_object_new_array();

		if (!sort_ctx.args)
			return ut_exception(s, op, UT_ERRMSG_OOM);
	}

	json_object_array_sort(arr, sort_fn);
	ut_putval(sort_ctx.args);

	return json_object_get(arr);
}

static struct json_object *
ut_splice(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *arr = json_object_array_get_idx(args, 0);
	int64_t off = ut_cast_int64(json_object_array_get_idx(args, 1));
	int64_t remlen = ut_cast_int64(json_object_array_get_idx(args, 2));
	size_t arrlen, addlen, idx;

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	arrlen = json_object_array_length(arr);
	addlen = json_object_array_length(args);

	if (addlen == 1) {
		off = 0;
		addlen = 0;
		remlen = arrlen;
	}
	else if (addlen == 2) {
		if (off < 0) {
			off = arrlen + off;

			if (off < 0)
				off = 0;
		}
		else if (off > arrlen) {
			off = arrlen;
		}

		addlen = 0;
		remlen = arrlen - off;
	}
	else {
		if (off < 0) {
			off = arrlen + off;

			if (off < 0)
				off = 0;
		}
		else if (off > arrlen) {
			off = arrlen;
		}

		if (remlen < 0) {
			remlen = arrlen - off + remlen;

			if (remlen < 0)
				remlen = 0;
		}
		else if (remlen > arrlen - off) {
			remlen = arrlen - off;
		}

		addlen -= 3;
	}

	if (addlen < remlen) {
		json_object_array_del_idx(arr, off, remlen - addlen);
	}
	else if (addlen > remlen) {
		for (idx = arrlen; idx > off; idx--)
			json_object_array_put_idx(arr, idx + addlen - remlen - 1,
				json_object_get(json_object_array_get_idx(arr, idx - 1)));
	}

	for (idx = 0; idx < addlen; idx++)
		json_object_array_put_idx(arr, off + idx,
			json_object_get(json_object_array_get_idx(args, 3 + idx)));

	return json_object_get(arr);
}

static struct json_object *
ut_split(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *sep = json_object_array_get_idx(args, 0);
	struct json_object *str = json_object_array_get_idx(args, 1);
	struct json_object *arr = NULL;
	const char *p, *sepstr, *splitstr;
	size_t seplen;

	if (!json_object_is_type(sep, json_type_string) || !json_object_is_type(str, json_type_string))
		return NULL;

	arr = json_object_new_array();

	if (!arr)
		return ut_exception(s, op, UT_ERRMSG_OOM);

	sepstr = json_object_get_string(sep);
	splitstr = json_object_get_string(str);

	for (p = splitstr + (*sepstr ? 1 : 0), seplen = strlen(sepstr); *p; p++) {
		if (!strncmp(p, sepstr, seplen)) {
			if (*sepstr || p > splitstr)
				json_object_array_add(arr, json_object_new_string_len(splitstr, p - splitstr));

			splitstr = p + seplen;
			p = splitstr - (*sepstr ? 1 : 0);
		}
	}

	if (*splitstr)
		json_object_array_add(arr, json_object_new_string_len(splitstr, p - splitstr));

	return arr;
}

static struct json_object *
ut_sqrt(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	double d = ut_cast_double(json_object_array_get_idx(args, 0));

	if (isnan(d))
		return json_object_new_double_rounded(NAN);

	return json_object_new_double_rounded(sqrt(d));
}

static struct json_object *
ut_substr(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *str = json_object_array_get_idx(args, 0);
	int64_t off = ut_cast_int64(json_object_array_get_idx(args, 1));
	int64_t sublen = ut_cast_int64(json_object_array_get_idx(args, 2));
	const char *p;
	size_t len;

	if (!json_object_is_type(str, json_type_string))
		return NULL;

	p = json_object_get_string(str);
	len = json_object_get_string_len(str);

	switch (json_object_array_length(args)) {
	case 1:
		off = 0;
		sublen = len;

		break;

	case 2:
		if (off < 0) {
			off = len + off;

			if (off < 0)
				off = 0;
		}
		else if (off > len) {
			off = len;
		}

		sublen = len - off;

		break;

	default:
		if (off < 0) {
			off = len + off;

			if (off < 0)
				off = 0;
		}
		else if (off > len) {
			off = len;
		}

		if (sublen < 0) {
			sublen = len - off + sublen;

			if (sublen < 0)
				sublen = 0;
		}
		else if (sublen > len - off) {
			sublen = len - off;
		}

		break;
	}

	return json_object_new_string_len(p + off, sublen);
}

static struct json_object *
ut_time(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	time_t t = time(NULL);

	return json_object_new_int64((int64_t)t);
}

static struct json_object *
ut_uc(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	const char *str = json_object_get_string(json_object_array_get_idx(args, 0));
	size_t len = str ? strlen(str) : 0;
	struct json_object *rv = NULL;
	char *res, *p;

	if (!str)
		return NULL;

	res = p = calloc(1, len);

	if (!res)
		return ut_exception(s, op, UT_ERRMSG_OOM);

	while (*str)
		if (*str >= 'a' && *str <= 'z')
			*p++ = *str++ - 32;
		else
			*p++ = *str++;

	rv = json_object_new_string_len(res, len);
	free(res);

	return rv;
}

static struct json_object *
ut_uchr(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	size_t len = json_object_array_length(args);
	size_t idx, ulen;
	char *p, *str;
	int64_t n;
	int rem;

	for (idx = 0, ulen = 0; idx < len; idx++) {
		n = ut_cast_int64(json_object_array_get_idx(args, idx));

		if (errno == EINVAL || errno == EOVERFLOW || n < 0 || n > 0x10FFFF)
			ulen += 3;
		else if (n <= 0x7F)
			ulen++;
		else if (n <= 0x7FF)
			ulen += 2;
		else if (n <= 0xFFFF)
			ulen += 3;
		else
			ulen += 4;
	}

	str = calloc(1, ulen);

	if (!str)
		return ut_exception(s, op, UT_ERRMSG_OOM);

	for (idx = 0, p = str, rem = ulen; idx < len; idx++) {
		n = ut_cast_int64(json_object_array_get_idx(args, idx));

		if (errno == EINVAL || errno == EOVERFLOW || n < 0 || n > 0x10FFFF)
			n = 0xFFFD;

		if (!utf8enc(&p, &rem, n))
			break;
	}

	return json_object_new_string_len(str, ulen);
}

static struct json_object *
ut_values(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *obj = json_object_array_get_idx(args, 0);
	struct json_object *arr;

	if (!json_object_is_type(obj, json_type_object))
		return NULL;

	arr = json_object_new_array();

	if (!arr)
		return ut_exception(s, op, UT_ERRMSG_OOM);

	json_object_object_foreach(obj, key, val) {
		(void)key;
		json_object_array_add(arr, json_object_get(val));
	}

	return arr;
}

static struct json_object *
ut_trim_common(struct ut_state *s, struct ut_opcode *op, struct json_object *args, bool start, bool end)
{
	struct json_object *str = json_object_array_get_idx(args, 0);
	struct json_object *chr = json_object_array_get_idx(args, 1);
	const char *p, *c;
	size_t len;

	if (!json_object_is_type(str, json_type_string) ||
		(chr != NULL && !json_object_is_type(chr, json_type_string)))
		return NULL;

	c = json_object_get_string(chr);
	c = c ? c : " \t\r\n";

	p = json_object_get_string(str);
	len = json_object_get_string_len(str);

	if (start) {
		while (*p) {
			if (!strchr(c, *p))
				break;

			p++;
			len--;
		}
	}

	if (end) {
		while (len > 0) {
			if (!strchr(c, p[len - 1]))
				break;

			len--;
		}
	}

	return json_object_new_string_len(p, len);
}

static struct json_object *
ut_trim(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	return ut_trim_common(s, op, args, true, true);
}

static struct json_object *
ut_ltrim(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	return ut_trim_common(s, op, args, true, false);
}

static struct json_object *
ut_rtrim(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	return ut_trim_common(s, op, args, false, true);
}

static const struct { const char *name; ut_c_fn *func; } functions[] = {
	{ "abs",		ut_abs },
	{ "atan2",		ut_atan2 },
	{ "chr",		ut_chr },
	{ "cos",		ut_cos },
	{ "delete",		ut_delete },
	{ "die",		ut_die },
	{ "exists",		ut_exists },
	{ "exit",		ut_exit },
	{ "exp",		ut_exp },
	{ "filter",		ut_filter },
	{ "getenv",		ut_getenv },
	{ "hex",		ut_hex },
	{ "index",		ut_lindex },
	{ "int",		ut_int },
	{ "join",		ut_join },
	{ "keys",		ut_keys },
	{ "lc",			ut_lc },
	{ "length",		ut_length },
	{ "log",		ut_log },
	{ "ltrim",		ut_ltrim },
	{ "map",		ut_map },
	{ "ord",		ut_ord },
	{ "pop",		ut_pop },
	{ "print",		ut_print },
	{ "push",		ut_push },
	{ "rand",		ut_rand },
	{ "reverse",	ut_reverse },
	{ "rindex",		ut_rindex },
	{ "rtrim",		ut_rtrim },
	{ "shift",		ut_shift },
	{ "sin",		ut_sin },
	{ "sort",		ut_sort },
	{ "splice",		ut_splice },
	{ "split",		ut_split },
	{ "sqrt",		ut_sqrt },
	{ "srand",		ut_srand },
	{ "substr",		ut_substr },
	{ "time",		ut_time },
	{ "trim",		ut_trim },
	{ "type",		ut_type },
	{ "uchr",		ut_uchr },
	{ "uc",			ut_uc },
	{ "unshift",	ut_unshift },
	{ "values",		ut_values },
};

static int
func_to_string(struct json_object *v, struct printbuf *pb, int level, int flags)
{
	return sprintbuf(pb, "%sfunction(...) { [native code] }%s",
		level ? "\"" : "", level ? "\"" : "");
}

static bool
add_function(struct ut_state *state, struct json_object *scope, const char *name, ut_c_fn *fn)
{
	struct ut_opcode *op = ut_new_op(state, T_FUNC,
		json_object_new_boolean(1),  (struct ut_opcode *)fn, (void *)1);

	json_object_set_serializer(op->val, func_to_string, op, NULL);

	return json_object_object_add(scope, name, json_object_get(op->val));
}

void
ut_lib_init(struct ut_state *state, struct json_object *scope)
{
	int i;

	for (i = 0; i < sizeof(functions) / sizeof(functions[0]); i++)
		add_function(state, scope, functions[i].name, functions[i].func);
}
