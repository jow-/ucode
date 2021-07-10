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

#include "ucode/util.h"
#include "ucode/chunk.h"
#include "ucode/value.h"
#include "ucode/vm.h"

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


bool
uc_val_is_truish(uc_value_t *val)
{
	double d;

	switch (ucv_type(val)) {
	case UC_INTEGER:
		if (ucv_is_u64(val))
			return (ucv_uint64_get(val) != 0);

		return (ucv_int64_get(val) != 0);

	case UC_DOUBLE:
		d = ucv_double_get(val);

		return (d != 0 && !isnan(d));

	case UC_BOOLEAN:
		return ucv_boolean_get(val);

	case UC_STRING:
		return (ucv_string_length(val) > 0);

	case UC_NULL:
		return false;

	default:
		return true;
	}
}

uc_type_t
uc_cast_number(uc_value_t *v, int64_t *n, double *d)
{
	bool is_double = false;
	const char *s;
	char *e;

	*d = 0.0;
	*n = 0;

	switch (ucv_type(v)) {
	case UC_INTEGER:
		*n = ucv_int64_get(v);

		return UC_INTEGER;

	case UC_DOUBLE:
		*d = ucv_double_get(v);

		return UC_DOUBLE;

	case UC_NULL:
		return UC_INTEGER;

	case UC_BOOLEAN:
		*n = ucv_boolean_get(v);

		return UC_INTEGER;

	case UC_STRING:
		s = ucv_string_get(v);

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

			return UC_DOUBLE;
		}

		if (is_double)
			return UC_DOUBLE;

		return UC_INTEGER;

	default:
		*d = NAN;

		return UC_DOUBLE;
	}
}

static char *
uc_tostring(uc_vm_t *vm, uc_value_t *val)
{
	if (ucv_type(val) != UC_STRING)
		return ucv_to_string(vm, val);

	return NULL;
}

static int64_t
uc_toidx(uc_value_t *val)
{
	const char *k;
	int64_t idx;
	double d;
	char *e;

	/* only consider doubles with integer values as array keys */
	if (ucv_type(val) == UC_DOUBLE) {
		d = ucv_double_get(val);

		if ((double)(int64_t)(d) != d)
			return -1;

		return (int64_t)d;
	}
	else if (ucv_type(val) == UC_INTEGER) {
		return ucv_int64_get(val);
	}
	else if (ucv_type(val) == UC_STRING) {
		errno = 0;
		k = ucv_string_get(val);
		idx = strtoll(k, &e, 0);

		if (errno != 0 || e == k || *e != 0)
			return -1;

		return idx;
	}

	return -1;
}

uc_value_t *
uc_getval(uc_vm_t *vm, uc_value_t *scope, uc_value_t *key)
{
	uc_value_t *o, *v = NULL;
	int64_t idx;
	bool found;
	char *k;

	if (ucv_type(scope) == UC_ARRAY) {
		idx = uc_toidx(key);

		if (idx >= 0 && (uint64_t)idx < ucv_array_length(scope))
			return ucv_get(ucv_array_get(scope, idx));
	}

	k = uc_tostring(vm, key);

	for (o = scope; o; o = ucv_prototype_get(o)) {
		if (ucv_type(o) != UC_OBJECT)
			continue;

		v = ucv_object_get(o, k ? k : ucv_string_get(key), &found);

		if (found)
			break;
	}

	free(k);

	return ucv_get(v);
}

uc_value_t *
uc_setval(uc_vm_t *vm, uc_value_t *scope, uc_value_t *key, uc_value_t *val)
{
	int64_t idx;
	char *s;
	bool rv;

	if (!key)
		return NULL;

	if (ucv_type(scope) == UC_ARRAY) {
		idx = uc_toidx(key);

		if (idx < 0 || !ucv_array_set(scope, idx, val))
			return NULL;

		return ucv_get(val);
	}

	s = uc_tostring(vm, key);
	rv = ucv_object_add(scope, s ? s : ucv_string_get(key), val);
	free(s);

	return rv ? ucv_get(val) : NULL;
}

bool
uc_delval(uc_vm_t *vm, uc_value_t *scope, uc_value_t *key)
{
	char *s;
	bool rv;

	if (!key)
		return NULL;

	s = uc_tostring(vm, key);
	rv = ucv_object_delete(scope, s ? s : ucv_string_get(key));
	free(s);

	return rv;
}

bool
uc_cmp(int how, uc_value_t *v1, uc_value_t *v2)
{
	uc_type_t t1 = ucv_type(v1);
	uc_type_t t2 = ucv_type(v2);
	int64_t n1, n2, delta;
	double d1, d2;

	if (t1 == UC_STRING && t2 == UC_STRING) {
		delta = strcmp(ucv_string_get(v1), ucv_string_get(v2));
	}
	else {
		if (t1 == t2 && !ucv_is_scalar(v1)) {
			delta = (intptr_t)v1 - (intptr_t)v2;
		}
		else {
			t1 = uc_cast_number(v1, &n1, &d1);
			t2 = uc_cast_number(v2, &n2, &d2);

			if (t1 == UC_DOUBLE || t2 == UC_DOUBLE) {
				d1 = (t1 == UC_DOUBLE) ? d1 : (double)n1;
				d2 = (t2 == UC_DOUBLE) ? d2 : (double)n2;

				/* all comparison results except `!=` involving NaN are false */
				if (isnan(d1) || isnan(d2))
					return (how == I_NE);

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
	case I_LT:
		return (delta < 0);

	case I_LE:
		return (delta <= 0);

	case I_GT:
		return (delta > 0);

	case I_GE:
		return (delta >= 0);

	case I_EQ:
		return (delta == 0);

	case I_NE:
		return (delta != 0);

	default:
		return false;
	}
}

void
uc_vallist_init(uc_value_list_t *list)
{
	list->isize = 0;
	list->dsize = 0;
	list->index = NULL;
	list->data = NULL;
}

void
uc_vallist_free(uc_value_list_t *list)
{
	uc_value_t *o;
	size_t i;

	for (i = 0; i < list->isize; i++) {
		if (TAG_GET_TYPE(list->index[i]) == TAG_PTR) {
			o = uc_vallist_get(list, i);
			ucv_put(o);
			ucv_put(o);
		}
	}

	free(list->index);
	free(list->data);
	uc_vallist_init(list);
}

static void
add_num(uc_value_list_t *list, int64_t n)
{
	size_t sz = TAG_ALIGN(sizeof(n));

	if (TAG_FIT_NV(n)) {
		list->index[list->isize++] = (TAG_TYPE)(TAG_NUM | TAG_SET_NV(n));
	}
	else {
		if ((TAG_TYPE)list->dsize + sz > TAG_MASK) {
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
find_num(uc_value_list_t *list, int64_t n)
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
add_dbl(uc_value_list_t *list, double d)
{
	size_t sz = TAG_ALIGN(sizeof(d));

	if ((TAG_TYPE)list->dsize + sz > TAG_MASK) {
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
find_dbl(uc_value_list_t *list, double d)
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
add_str(uc_value_list_t *list, const char *s, size_t slen)
{
	uint32_t sl;
	size_t sz;
	char *dst;
	size_t i;

	if (slen > UINT32_MAX) {
		fprintf(stderr, "String constant too long\n");
		abort();
	}

	sz = TAG_ALIGN(sizeof(uint32_t) + slen);

	if ((TAG_TYPE)list->dsize + sz > TAG_MASK) {
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
find_str(uc_value_list_t *list, const char *s, size_t slen)
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
add_ptr(uc_value_list_t *list, void *ptr)
{
	size_t sz = TAG_ALIGN(sizeof(ptr));

	if ((TAG_TYPE)list->dsize + sz > TAG_MASK) {
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
uc_vallist_add(uc_value_list_t *list, uc_value_t *value)
{
	ssize_t existing;

	if ((list->isize % UC_VALLIST_CHUNK_SIZE) == 0) {
		list->index = xrealloc(list->index, sizeof(list->index[0]) * (list->isize + UC_VALLIST_CHUNK_SIZE));
		memset(&list->index[list->isize], 0, UC_VALLIST_CHUNK_SIZE);
	}

	switch (ucv_type(value)) {
	case UC_INTEGER:
		/* XXX: u64 */
		existing = find_num(list, ucv_int64_get(value));

		if (existing > -1)
			return existing;

		add_num(list, ucv_int64_get(value));

		break;

	case UC_DOUBLE:
		existing = find_dbl(list, ucv_double_get(value));

		if (existing > -1)
			return existing;

		add_dbl(list, ucv_double_get(value));

		break;

	case UC_STRING:
		existing = find_str(list,
			ucv_string_get(value),
			ucv_string_length(value));

		if (existing > -1)
			return existing;

		add_str(list,
			ucv_string_get(value),
			ucv_string_length(value));

		break;

	case UC_FUNCTION:
		add_ptr(list, value);
		break;

	default:
		return -1;
	}

	return (ssize_t)list->isize - 1;
}

uc_value_type_t
uc_vallist_type(uc_value_list_t *list, size_t idx)
{
	if (idx >= list->isize)
		return TAG_INVAL;

	return TAG_GET_TYPE(list->index[idx]);
}

uc_value_t *
uc_vallist_get(uc_value_list_t *list, size_t idx)
{
	char str[sizeof(TAG_TYPE)];
	size_t n, len;

	switch (uc_vallist_type(list, idx)) {
	case TAG_NUM:
		return ucv_int64_new(TAG_GET_NV(list->index[idx]));

	case TAG_LNUM:
		if (TAG_GET_OFFSET(list->index[idx]) + sizeof(int64_t) > list->dsize)
			return NULL;

		/* XXX: u64 */
		return ucv_int64_new(be64toh(*(int64_t *)(list->data + TAG_GET_OFFSET(list->index[idx]))));

	case TAG_DBL:
		if (TAG_GET_OFFSET(list->index[idx]) + sizeof(double) > list->dsize)
			return NULL;

		return ucv_double_new(*(double *)(list->data + TAG_GET_OFFSET(list->index[idx])));

	case TAG_STR:
		len = TAG_GET_STR_L(list->index[idx]);

		for (n = 0; n < len; n++)
			str[n] = (list->index[idx] >> ((n + 1) << 3));

		return ucv_string_new_length(str, len);

	case TAG_LSTR:
		if (TAG_GET_OFFSET(list->index[idx]) + sizeof(uint32_t) > list->dsize)
			return NULL;

		len = (size_t)be32toh(*(uint32_t *)(list->data + TAG_GET_OFFSET(list->index[idx])));

		if (TAG_GET_OFFSET(list->index[idx]) + sizeof(uint32_t) + len > list->dsize)
			return NULL;

		return ucv_string_new_length(list->data + TAG_GET_OFFSET(list->index[idx]) + sizeof(uint32_t), len);

	case TAG_PTR:
		if (TAG_GET_OFFSET(list->index[idx]) + sizeof(void *) > list->dsize)
			return NULL;

		return ucv_get(*(uc_value_t **)(list->data + TAG_GET_OFFSET(list->index[idx])));

	default:
		return NULL;
	}
}
