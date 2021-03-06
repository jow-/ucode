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
#include "ucode/vallist.h"
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
