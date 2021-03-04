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

#include <string.h> /* memcpy(), memset() */
#include <endian.h> /* htobe64(), be64toh() */
#include <math.h> /* isnan(), INFINITY */
#include <ctype.h> /* isspace(), isdigit(), isxdigit() */
#include <errno.h>

#include "util.h"
#include "chunk.h"
#include "value.h"
#include "object.h"
#include "lexer.h" /* TK_* */

#define TAG_TYPE			uint64_t
#define TAG_BITS			3
#define TAG_MASK			((1LL << ((sizeof(TAG_TYPE) << 3) - TAG_BITS)) - 1)
#define TAG_MAXN			(TAG_MASK / 2)
#define TAG_ALIGN(s)		(((s) + (1 << TAG_BITS) - 1) & -(1 << TAG_BITS))
#define TAG_GET_TYPE(n)		(int)((TAG_TYPE)n & ((1 << TAG_BITS) - 1))
#define TAG_FIT_NV(n)		((int64_t)n >= -TAG_MAXN && (int64_t)n <= TAG_MAXN)
#define TAG_SET_NV(n)		((TAG_TYPE)((int64_t)n + TAG_MAXN) << TAG_BITS)
#define TAG_GET_NV(n)		(int64_t)((int64_t)(((TAG_TYPE)n >> TAG_BITS) & TAG_MASK) - TAG_MAXN)
#define TAG_FIT_STR(l)		((l - 1) < (((sizeof(TAG_TYPE) << 3) - TAG_BITS) >> 3))
#define TAG_SET_STR_L(l)	(TAG_TYPE)((l & ((1 << (8 - TAG_BITS)) - 1)) << TAG_BITS)
#define TAG_GET_STR_L(n)	(size_t)(((TAG_TYPE)n >> TAG_BITS) & ((1 << (8 - TAG_BITS)) - 1))
#define TAG_GET_BOOL(n)		(bool)(((TAG_TYPE)n >> TAG_BITS) & 1)
#define TAG_GET_OFFSET(n)	(size_t)(((TAG_TYPE)n >> TAG_BITS) & TAG_MASK)

#define UC_VALLIST_CHUNK_SIZE	8


static int
uc_double_tostring(json_object *v, struct printbuf *pb, int level, int flags)
{
	bool strict = (level > 0) || (flags & JSON_C_TO_STRING_STRICT);
	double d = json_object_get_double(v);

	if (isnan(d))
		return sprintbuf(pb, strict ? "\"NaN\"" : "NaN");

	if (d == INFINITY)
		return sprintbuf(pb, strict ? "1e309" : "Infinity");

	if (d == -INFINITY)
		return sprintbuf(pb, strict ? "-1e309" : "-Infinity");

	return sprintbuf(pb, "%g", d);
}

json_object *
uc_double_new(double v)
{
	json_object *d = json_object_new_double(v);

	if (!d) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	json_object_set_serializer(d, uc_double_tostring, NULL, NULL);

	return d;
}

bool
uc_val_is_truish(json_object *val)
{
	double d;

	switch (json_object_get_type(val)) {
	case json_type_int:
		return (json_object_get_int64(val) != 0);

	case json_type_double:
		d = json_object_get_double(val);

		return (d != 0 && !isnan(d));

	case json_type_boolean:
		return (json_object_get_boolean(val) != false);

	case json_type_string:
		return (json_object_get_string_len(val) > 0);

	case json_type_array:
	case json_type_object:
		return true;

	default:
		return false;
	}
}

enum json_type
uc_cast_number(json_object *v, int64_t *n, double *d)
{
	bool is_double = false;
	const char *s;
	char *e;

	*d = 0.0;
	*n = 0;

	switch (json_object_get_type(v)) {
	case json_type_int:
		*n = json_object_get_int64(v);

		return json_type_int;

	case json_type_double:
		*d = json_object_get_double(v);

		return json_type_double;

	case json_type_null:
		return json_type_int;

	case json_type_boolean:
		*n = json_object_get_boolean(v) ? 1 : 0;

		return json_type_int;

	case json_type_string:
		s = json_object_get_string(v);

		while (isspace(*s))
			s++;

		if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X') && isxdigit(s[2])) {
			*n = strtoll(s, &e, 16);
		}
		else if (s[0] == '0' && isdigit(s[2])) {
			*n = strtoll(s, &e, 8);
		}
		else {
			*n = strtoll(s, &e, 10);

			if (*e == '.') {
				*d = strtod(s, &e);
				is_double = (e > s);
			}
		}

		while (isspace(*e))
			e++;

		if (*e) {
			*d = NAN;

			return json_type_double;
		}

		if (is_double)
			return json_type_double;

		return json_type_int;

	default:
		*d = NAN;

		return json_type_double;
	}
}

static json_object *
uc_getproto(json_object *obj)
{
	uc_prototype *proto;

	switch (uc_object_type(obj)) {
	case UC_OBJ_RESSOURCE:
		proto = uc_ressource_prototype(obj);
		break;

	case UC_OBJ_PROTOTYPE:
		proto = uc_object_as_prototype(obj)->parent;
		break;

	default:
		proto = NULL;
	}

	return proto ? proto->header.jso : NULL;
}

json_object *
uc_getval(json_object *scope, json_object *key)
{
	json_object *o, *v;
	const char *k;
	int64_t idx;
	double d;

	if (json_object_is_type(scope, json_type_array)) {
		/* only consider doubles with integer values as array keys */
		if (json_object_is_type(key, json_type_double)) {
			d = json_object_get_double(key);

			if ((double)(int64_t)(d) == d)
				idx = (int64_t)d;
			else
				idx = -1;
		}
		else {
			errno = 0;
			idx = json_object_get_int64(key);

			if (errno != 0)
				idx = -1;
		}

		if (idx >= 0 && idx < json_object_array_length(scope))
			return json_object_get(json_object_array_get_idx(scope, idx));
	}

	for (o = scope, k = key ? json_object_get_string(key) : "null"; o; o = uc_getproto(o)) {
		if (!json_object_is_type(o, json_type_object))
			continue;

		if (json_object_object_get_ex(o, k, &v))
			return json_object_get(v);
	}

	return NULL;
}

json_object *
uc_setval(json_object *scope, json_object *key, json_object *val)
{
	int64_t idx;

	if (!key)
		return NULL;

	if (json_object_is_type(scope, json_type_array)) {
		errno = 0;
		idx = json_object_get_int64(key);

		if (errno != 0)
			return NULL;

		if (json_object_array_put_idx(scope, idx, val))
			return NULL;

		return json_object_get(val);
	}

	if (json_object_object_add(scope, key ? json_object_get_string(key) : "null", val))
		return NULL;

	return json_object_get(val);
}

bool
uc_cmp(int how, json_object *v1, json_object *v2)
{
	enum json_type t1 = json_object_get_type(v1);
	enum json_type t2 = json_object_get_type(v2);
	int64_t n1, n2, delta;
	double d1, d2;

	if (t1 == json_type_string && t2 == json_type_string) {
		delta = strcmp(json_object_get_string(v1), json_object_get_string(v2));
	}
	else {
		if ((t1 == json_type_array && t2 == json_type_array) ||
		    (t1 == json_type_object && t2 == json_type_object))	{
			delta = (void *)v1 - (void *)v2;
		}
		else {
			t1 = uc_cast_number(v1, &n1, &d1);
			t2 = uc_cast_number(v2, &n2, &d2);

			if (t1 == json_type_double || t2 == json_type_double) {
				d1 = (t1 == json_type_double) ? d1 : (double)n1;
				d2 = (t2 == json_type_double) ? d2 : (double)n2;

				if (d1 == d2)
					delta = 0;
				else if (d1 < d2)
					delta = -1;
				else
					delta = 1;
			}
			else {
				delta = n1 - n2;
			}
		}
	}

	switch (how) {
	case TK_LT:
		return (delta < 0);

	case TK_LE:
		return (delta <= 0);

	case TK_GT:
		return (delta > 0);

	case TK_GE:
		return (delta >= 0);

	case TK_EQ:
		return (delta == 0);

	case TK_NE:
		return (delta != 0);

	default:
		return false;
	}
}

bool
uc_eq(json_object *v1, json_object *v2)
{
	uc_objtype_t o1 = uc_object_type(v1);
	uc_objtype_t o2 = uc_object_type(v2);
	enum json_type t1 = json_object_get_type(v1);
	enum json_type t2 = json_object_get_type(v2);

	if (o1 != o2 || t1 != t2)
		return false;

	switch (t1) {
	case json_type_array:
	case json_type_object:
		return (v1 == v2);

	case json_type_boolean:
		return (json_object_get_boolean(v1) == json_object_get_boolean(v2));

	case json_type_double:
		if (isnan(json_object_get_double(v1)) || isnan(json_object_get_double(v2)))
			return false;

		return (json_object_get_double(v1) == json_object_get_double(v2));

	case json_type_int:
		return (json_object_get_int64(v1) == json_object_get_int64(v2));

	case json_type_string:
		return !strcmp(json_object_get_string(v1), json_object_get_string(v2));

	case json_type_null:
		return true;
	}

	return false;
}

void
uc_vallist_init(uc_value_list *list)
{
	list->isize = 0;
	list->dsize = 0;
	list->index = NULL;
	list->data = NULL;
}

void
uc_vallist_free(uc_value_list *list)
{
	json_object *o;
	size_t i;

	for (i = 0; i < list->isize; i++) {
		if (TAG_GET_TYPE(list->index[i]) == TAG_PTR) {
			o = uc_vallist_get(list, i);
			uc_value_put(o);
			uc_value_put(o);
		}
	}

	free(list->index);
	free(list->data);
	uc_vallist_init(list);
}

static void
add_num(uc_value_list *list, int64_t n)
{
	size_t sz = TAG_ALIGN(sizeof(n));

	if (TAG_FIT_NV(n)) {
		list->index[list->isize++] = (TAG_TYPE)(TAG_NUM | TAG_SET_NV(n));
	}
	else {
		if (list->dsize + sz > TAG_MASK) {
			fprintf(stderr, "Constant data too large\n");
			abort();
		}

		list->data = xrealloc(list->data, list->dsize + sz);

		n = htobe64(n);
		memset(list->data + list->dsize, 0, sz);
		memcpy(list->data + list->dsize, &n, sizeof(n));

		list->index[list->isize++] = (TAG_TYPE)(TAG_LNUM | (list->dsize << TAG_BITS));
		list->dsize += sz;
	}
}

static ssize_t
find_num(uc_value_list *list, int64_t n)
{
	TAG_TYPE search;
	size_t i;

	if (TAG_FIT_NV(n)) {
		search = (TAG_TYPE)(TAG_NUM | TAG_SET_NV(n));

		for (i = 0; i < list->isize; i++)
			if (list->index[i] == search)
				return i;
	}
	else {
		for (i = 0; i < list->isize; i++) {
			if (TAG_GET_TYPE(list->index[i]) != TAG_LNUM)
				continue;

			if (TAG_GET_OFFSET(list->index[i]) + sizeof(int64_t) > list->dsize)
				continue;

			if ((int64_t)be64toh(*(int64_t *)(list->data + TAG_GET_OFFSET(list->index[i]))) != n)
				continue;

			return i;
		}
	}

	return -1;
}

static void
add_dbl(uc_value_list *list, double d)
{
	size_t sz = TAG_ALIGN(sizeof(d));

	if (list->dsize + sz > TAG_MASK) {
		fprintf(stderr, "Constant data too large\n");
		abort();
	}

	list->data = xrealloc(list->data, list->dsize + sz);

	memset(list->data + list->dsize, 0, sz);
	memcpy(list->data + list->dsize, &d, sizeof(d));

	list->index[list->isize++] = (uint64_t)(TAG_DBL | (list->dsize << TAG_BITS));
	list->dsize += sz;
}

static ssize_t
find_dbl(uc_value_list *list, double d)
{
	size_t i;

	for (i = 0; i < list->isize; i++) {
		if (TAG_GET_TYPE(list->index[i]) != TAG_DBL)
			continue;

		if (TAG_GET_OFFSET(list->index[i]) + sizeof(double) > list->dsize)
			continue;

		if (*(double *)(list->data + TAG_GET_OFFSET(list->index[i])) != d)
			continue;

		return i;
	}

	return -1;
}

static void
add_str(uc_value_list *list, const char *s, size_t slen)
{
	uint32_t sl;
	size_t sz;
	char *dst;
	int i;

	if (slen > UINT32_MAX) {
		fprintf(stderr, "String constant too long\n");
		abort();
	}

	sz = TAG_ALIGN(sizeof(uint32_t) + slen);

	if (list->dsize + sz > TAG_MASK) {
		fprintf(stderr, "Constant data too large\n");
		abort();
	}

	if (TAG_FIT_STR(slen)) {
		list->index[list->isize] = (uint64_t)(TAG_STR | TAG_SET_STR_L(slen));

		for (i = 0; i < slen; i++)
			list->index[list->isize] |= (((TAG_TYPE)s[i] << ((i + 1) << 3)));

		list->isize++;
	}
	else {
		list->data = xrealloc(list->data, list->dsize + sz);

		sl = htobe32(slen);
		dst = list->data + list->dsize;
		memcpy(dst, &sl, sizeof(sl));

		dst += sizeof(sl);
		memcpy(dst, s, slen);

		dst += slen;
		memset(dst, 0, TAG_ALIGN(sizeof(uint32_t) + slen) - (sizeof(uint32_t) + slen));

		list->index[list->isize++] = (uint64_t)(TAG_LSTR | (list->dsize << TAG_BITS));
		list->dsize += sz;
	}
}

static ssize_t
find_str(uc_value_list *list, const char *s, size_t slen)
{
	TAG_TYPE search;
	size_t i, len;

	if (TAG_FIT_STR(slen)) {
		search = (TAG_TYPE)(TAG_STR | TAG_SET_STR_L(slen));

		for (i = 0; i < slen; i++)
			search |= (((TAG_TYPE)s[i] << ((i + 1) << 3)));

		for (i = 0; i < list->isize; i++)
			if (list->index[i] == search)
				return i;
	}
	else {
		for (i = 0; i < list->isize; i++) {
			if (TAG_GET_TYPE(list->index[i]) != TAG_LSTR)
				continue;

			if (TAG_GET_OFFSET(list->index[i]) + sizeof(uint32_t) > list->dsize)
				continue;

			len = (size_t)be32toh(*(uint32_t *)(list->data + TAG_GET_OFFSET(list->index[i])));

			if (len != slen)
				continue;

			if (TAG_GET_OFFSET(list->index[i]) + sizeof(uint32_t) + len > list->dsize)
				continue;

			if (memcmp(list->data + TAG_GET_OFFSET(list->index[i]) + sizeof(uint32_t), s, slen))
				continue;

			return i;
		}
	}

	return -1;
}

static void
add_ptr(uc_value_list *list, void *ptr)
{
	size_t sz = TAG_ALIGN(sizeof(ptr));

	if (list->dsize + sz > TAG_MASK) {
		fprintf(stderr, "Constant data too large\n");
		abort();
	}

	list->data = xrealloc(list->data, list->dsize + sz);

	memset(list->data + list->dsize, 0, sz);
	memcpy(list->data + list->dsize, &ptr, sizeof(ptr));

	list->index[list->isize++] = (uint64_t)(TAG_PTR | (list->dsize << TAG_BITS));
	list->dsize += sz;
}

ssize_t
uc_vallist_add(uc_value_list *list, json_object *value)
{
	ssize_t existing;

	if ((list->isize % UC_VALLIST_CHUNK_SIZE) == 0) {
		list->index = xrealloc(list->index, sizeof(list->index[0]) * (list->isize + UC_VALLIST_CHUNK_SIZE));
		memset(&list->index[list->isize], 0, UC_VALLIST_CHUNK_SIZE);
	}

	switch (json_object_get_type(value)) {
	case json_type_int:
		existing = find_num(list, json_object_get_int64(value));

		if (existing > -1)
			return existing;

		add_num(list, json_object_get_int64(value));

		break;

	case json_type_double:
		existing = find_dbl(list, json_object_get_double(value));

		if (existing > -1)
			return existing;

		add_dbl(list, json_object_get_double(value));

		break;

	case json_type_string:
		existing = find_str(list,
			json_object_get_string(value),
			json_object_get_string_len(value));

		if (existing > -1)
			return existing;

		add_str(list,
			json_object_get_string(value),
			json_object_get_string_len(value));

		break;

	case json_type_object:
		add_ptr(list, value);
		break;

	default:
		return -1;
	}

	return (ssize_t)list->isize - 1;
}

uc_value_type_t
uc_vallist_type(uc_value_list *list, size_t idx)
{
	if (idx >= list->isize)
		return TAG_INVAL;

	return TAG_GET_TYPE(list->index[idx]);
}

json_object *
uc_vallist_get(uc_value_list *list, size_t idx)
{
	char str[sizeof(TAG_TYPE)];
	size_t len;
	int n;

	switch (uc_vallist_type(list, idx)) {
	case TAG_NUM:
		return xjs_new_int64(TAG_GET_NV(list->index[idx]));

	case TAG_LNUM:
		if (TAG_GET_OFFSET(list->index[idx]) + sizeof(int64_t) > list->dsize)
			return NULL;

		return xjs_new_int64(be64toh(*(int64_t *)(list->data + TAG_GET_OFFSET(list->index[idx]))));

	case TAG_DBL:
		if (TAG_GET_OFFSET(list->index[idx]) + sizeof(double) > list->dsize)
			return NULL;

		return uc_double_new(*(double *)(list->data + TAG_GET_OFFSET(list->index[idx])));

	case TAG_STR:
		len = TAG_GET_STR_L(list->index[idx]);

		for (n = 0; n < len; n++)
			str[n] = (list->index[idx] >> ((n + 1) << 3));

		return xjs_new_string_len(str, len);

	case TAG_LSTR:
		if (TAG_GET_OFFSET(list->index[idx]) + sizeof(uint32_t) > list->dsize)
			return NULL;

		len = (size_t)be32toh(*(uint32_t *)(list->data + TAG_GET_OFFSET(list->index[idx])));

		if (TAG_GET_OFFSET(list->index[idx]) + sizeof(uint32_t) + len > list->dsize)
			return NULL;

		return xjs_new_string_len(list->data + TAG_GET_OFFSET(list->index[idx]) + sizeof(uint32_t), len);

	case TAG_PTR:
		if (TAG_GET_OFFSET(list->index[idx]) + sizeof(void *) > list->dsize)
			return NULL;

		return uc_value_get(*(json_object **)(list->data + TAG_GET_OFFSET(list->index[idx])));

	default:
		return NULL;
	}
}
