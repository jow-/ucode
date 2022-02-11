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
#include <assert.h>
#include <errno.h>
#include <assert.h>

#include "ucode/util.h"
#include "ucode/chunk.h"
#include "ucode/program.h"
#include "ucode/vallist.h"
#include "ucode/vm.h"

#define TAG_TYPE			uint64_t
#define TAG_BITS			3
#define TAG_MASK			((1LL << ((sizeof(TAG_TYPE) << 3) - TAG_BITS)) - 1)
#define TAG_ALIGN(s)		(((s) + (1 << TAG_BITS) - 1) & -(1 << TAG_BITS))
#define TAG_GET_TYPE(n)		(int)((TAG_TYPE)n & ((1 << TAG_BITS) - 1))
#define TAG_FIT_NV(n)		((uint64_t)n <= TAG_MASK)
#define TAG_SET_NV(n)		((TAG_TYPE)(uint64_t)n << TAG_BITS)
#define TAG_GET_NV(n)		(uint64_t)((uint64_t)((TAG_TYPE)n >> TAG_BITS) & TAG_MASK)
#define TAG_FIT_STR(l)		((l - 1) < (((sizeof(TAG_TYPE) << 3) - TAG_BITS) >> 3))
#define TAG_SET_STR_L(l)	(TAG_TYPE)((l & ((1 << (8 - TAG_BITS)) - 1)) << TAG_BITS)
#define TAG_GET_STR_L(n)	(size_t)(((TAG_TYPE)n >> TAG_BITS) & ((1 << (8 - TAG_BITS)) - 1))
#define TAG_GET_BOOL(n)		(bool)(((TAG_TYPE)n >> TAG_BITS) & 1)
#define TAG_GET_OFFSET(n)	(size_t)(((TAG_TYPE)n >> TAG_BITS) & TAG_MASK)

#define UC_VALLIST_CHUNK_SIZE	8


uc_value_t *
uc_number_parse(const char *buf, char **end)
{
	unsigned long long u;
	const char *p = buf;
	bool neg = false;
	double d;
	char *e;

	while (isspace(*p))
		p++;

	if (*p == '-') {
		neg = true;
		p++;
	}

	if (*p != 0 && !isxdigit(*p))
		return NULL;

	if (!end)
		end = &e;

	u = strtoull(p, end, 0);

	if (**end == '.' || **end == 'e' || **end == 'E') {
		d = strtod(p, end);

		if (!isspace(**end) && **end != 0)
			return NULL;

		if (neg)
			d = -d;

		return ucv_double_new(d);
	}

	if (!isspace(**end) && **end != 0)
		return NULL;

	if (neg) {
		if (u > INT64_MAX)
			return ucv_int64_new(INT64_MIN);

		return ucv_int64_new(-(int64_t)u);
	}

	return ucv_uint64_new(u);
}

bool
uc_double_pack(double d, char *buf, bool little_endian)
{
	int8_t step = little_endian ? -1 : 1;
	uint32_t hibits = 0, lobits = 0;
	int32_t exponent = 0;
	bool sign = false;
	double fraction;
	uint8_t *p;

	if (d == 0.0) {
		sign = (copysign(1.0, d) == -1.0);
	}
	else if (isnan(d)) {
		sign = (copysign(1.0, d) == -1.0);
		exponent = 0x7ff;
		lobits = 0x1000000;
		hibits = 0xfffffff;
	}
	else if (!isfinite(d)) {
		sign = (d < 0.0);
		exponent = 0x7ff;
	}
	else {
		if (d < 0.0) {
			sign = true;
			d = -d;
		}

		fraction = frexp(d, &exponent);

		if (fraction == 0.0) {
			exponent = 0;
		}
		else {
			assert(fraction >= 0.5 && fraction < 1.0);

			fraction *= 2.0;
			exponent--;
		}

		if (exponent >= 1024) {
			errno = ERANGE;

			return false;
		}
		else if (exponent < -1022) {
			fraction = ldexp(fraction, 1022 + exponent);
			exponent = 0;
		}
		else if (exponent != 0 || fraction != 0.0) {
			fraction -= 1.0;
			exponent += 1023;
		}

		fraction *= 268435456.0;
		hibits = (uint32_t)fraction;
		assert(hibits <= 0xfffffff);

		fraction -= (double)hibits;
		fraction *= 16777216.0;
		lobits = (uint32_t)(fraction + 0.5);
		assert(lobits <= 0x1000000);

		if (lobits >> 24) {
			lobits = 0;

			if (++hibits >> 28) {
				hibits = 0;

				if (++exponent >= 2047) {
					errno = ERANGE;

					return false;
				}
			}
		}
	}

	p = (uint8_t *)buf + (little_endian ? 7 : 0);
	*p = (sign << 7) | (exponent >> 4);

	p += step;
	*p = ((exponent & 0xf) << 4) | (hibits >> 24);

	p += step;
	*p = (hibits >> 16) & 0xff;

	p += step;
	*p = (hibits >> 8) & 0xff;

	p += step;
	*p = hibits & 0xff;

	p += step;
	*p = (lobits >> 16) & 0xff;

	p += step;
	*p = (lobits >> 8) & 0xff;

	p += step;
	*p = lobits & 0xff;

	return true;
}

double
uc_double_unpack(const char *buf, bool little_endian)
{
	int8_t step = little_endian ? -1 : 1;
	uint32_t lofrac, hifrac;
	int32_t exponent;
	uint8_t *p;
	bool sign;
	double d;

	p = (uint8_t *)buf + (little_endian ? 7 : 0);
	sign = (*p >> 7) & 1;
	exponent = (*p & 0x7f) << 4;

	p += step;
	exponent |= (*p >> 4) & 0xf;
	hifrac = (*p & 0xf) << 24;

	p += step;
	hifrac |= *p << 16;

	p += step;
	hifrac |= *p << 8;

	p += step;
	hifrac |= *p;

	p += step;
	lofrac = *p << 16;

	p += step;
	lofrac |= *p << 8;

	p += step;
	lofrac |= *p;

	if (exponent == 0x7ff) {
		if (lofrac == 0 && hifrac == 0)
			return sign ? -INFINITY : INFINITY;
		else
			return sign ? -NAN : NAN;
	}

	d = (double)hifrac + (double)lofrac / 16777216.0;
	d /= 268435456.0;

	if (exponent == 0) {
		exponent = -1022;
	}
	else {
		exponent -= 1023;
		d += 1.0;
	}

	d = ldexp(d, exponent);

	return sign ? -d : d;
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
	free(list->index);
	free(list->data);
	uc_vallist_init(list);
}

static void
add_num(uc_value_list_t *list, uint64_t n)
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
find_num(uc_value_list_t *list, uint64_t n)
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

			if (TAG_GET_OFFSET(list->index[i]) + sizeof(uint64_t) > list->dsize)
				continue;

			if ((uint64_t)be64toh(*(uint64_t *)(list->data + TAG_GET_OFFSET(list->index[i]))) != n)
				continue;

			return i;
		}
	}

	return -1;
}

static void
add_dbl(uc_value_list_t *list, double d)
{
	size_t sz = TAG_ALIGN(sizeof(uint64_t));

	if ((TAG_TYPE)list->dsize + sz > TAG_MASK) {
		fprintf(stderr, "Constant data too large\n");
		abort();
	}

	list->data = xrealloc(list->data, list->dsize + sz);

	memset(list->data + list->dsize, 0, sz);

	if (!uc_double_pack(d, list->data + list->dsize, false)) {
		fprintf(stderr, "Double value not representable\n");
		abort();
	}

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

		if (TAG_GET_OFFSET(list->index[i]) + sizeof(uint64_t) > list->dsize)
			continue;

		if (uc_double_unpack(list->data + TAG_GET_OFFSET(list->index[i]), false) != d)
			continue;

		return i;
	}

	return -1;
}

static void
add_str(uc_value_list_t *list, const char *s, size_t slen)
{
	const uint8_t *u8 = (const uint8_t *)s;
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
			list->index[list->isize] |= (((TAG_TYPE)u8[i] << ((i + 1) << 3)));

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
	const uint8_t *u8 = (const uint8_t *)s;
	TAG_TYPE search;
	size_t i, len;

	if (TAG_FIT_STR(slen)) {
		search = (TAG_TYPE)(TAG_STR | TAG_SET_STR_L(slen));

		for (i = 0; i < slen; i++)
			search |= (((TAG_TYPE)u8[i] << ((i + 1) << 3)));

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

ssize_t
uc_vallist_add(uc_value_list_t *list, uc_value_t *value)
{
	ssize_t existing;
	uint64_t u64;

	if ((list->isize % UC_VALLIST_CHUNK_SIZE) == 0) {
		list->index = xrealloc(list->index, sizeof(list->index[0]) * (list->isize + UC_VALLIST_CHUNK_SIZE));
		memset(&list->index[list->isize], 0, UC_VALLIST_CHUNK_SIZE);
	}

	switch (ucv_type(value)) {
	case UC_INTEGER:
		u64 = ucv_uint64_get(value);

		assert(errno == 0);

		existing = find_num(list, u64);

		if (existing > -1)
			return existing;

		add_num(list, u64);

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
	uint8_t str[sizeof(TAG_TYPE)];
	size_t n, len;

	switch (uc_vallist_type(list, idx)) {
	case TAG_NUM:
		return ucv_uint64_new(TAG_GET_NV(list->index[idx]));

	case TAG_LNUM:
		if (TAG_GET_OFFSET(list->index[idx]) + sizeof(uint64_t) > list->dsize)
			return NULL;

		return ucv_uint64_new(be64toh(*(uint64_t *)(list->data + TAG_GET_OFFSET(list->index[idx]))));

	case TAG_DBL:
		if (TAG_GET_OFFSET(list->index[idx]) + sizeof(double) > list->dsize)
			return NULL;

		return ucv_double_new(uc_double_unpack(list->data + TAG_GET_OFFSET(list->index[idx]), false));

	case TAG_STR:
		len = TAG_GET_STR_L(list->index[idx]);

		for (n = 0; n < len; n++)
			str[n] = (list->index[idx] >> ((n + 1) << 3));

		return ucv_string_new_length((char *)str, len);

	case TAG_LSTR:
		if (TAG_GET_OFFSET(list->index[idx]) + sizeof(uint32_t) > list->dsize)
			return NULL;

		len = (size_t)be32toh(*(uint32_t *)(list->data + TAG_GET_OFFSET(list->index[idx])));

		if (TAG_GET_OFFSET(list->index[idx]) + sizeof(uint32_t) + len > list->dsize)
			return NULL;

		return ucv_string_new_length(list->data + TAG_GET_OFFSET(list->index[idx]) + sizeof(uint32_t), len);

	default:
		return NULL;
	}
}
