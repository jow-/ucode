/*
 * Binary data packing/unpacking module for ucode.
 * Copyright (C) 2021 Jo-Philipp Wich <jo@mein.io>
 *
 * This module is heavily based on the Python 3.10 "_struct.c" module source
 * published under the following license:
 *
 * -----------------------------------------------------------------------------------
 *
 * 1. This LICENSE AGREEMENT is between the Python Software Foundation ("PSF"), and
 *    the Individual or Organization ("Licensee") accessing and otherwise using Python
 *    3.10.0 software in source or binary form and its associated documentation.
 *
 * 2. Subject to the terms and conditions of this License Agreement, PSF hereby
 *    grants Licensee a nonexclusive, royalty-free, world-wide license to reproduce,
 *    analyze, test, perform and/or display publicly, prepare derivative works,
 *    distribute, and otherwise use Python 3.10.0 alone or in any derivative
 *    version, provided, however, that PSF's License Agreement and PSF's notice of
 *    copyright, i.e., "Copyright © 2001-2021 Python Software Foundation; All Rights
 *    Reserved" are retained in Python 3.10.0 alone or in any derivative version
 *    prepared by Licensee.
 *
 * 3. In the event Licensee prepares a derivative work that is based on or
 *    incorporates Python 3.10.0 or any part thereof, and wants to make the
 *    derivative work available to others as provided herein, then Licensee hereby
 *    agrees to include in any such work a brief summary of the changes made to Python
 *    3.10.0.
 *
 * 4. PSF is making Python 3.10.0 available to Licensee on an "AS IS" basis.
 *    PSF MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED.  BY WAY OF
 *    EXAMPLE, BUT NOT LIMITATION, PSF MAKES NO AND DISCLAIMS ANY REPRESENTATION OR
 *    WARRANTY OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE OR THAT THE
 *    USE OF PYTHON 3.10.0 WILL NOT INFRINGE ANY THIRD PARTY RIGHTS.
 *
 * 5. PSF SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF PYTHON 3.10.0
 *    FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS AS A RESULT OF
 *    MODIFYING, DISTRIBUTING, OR OTHERWISE USING PYTHON 3.10.0, OR ANY DERIVATIVE
 *    THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.
 *
 * 6. This License Agreement will automatically terminate upon a material breach of
 *    its terms and conditions.
 *
 * 7. Nothing in this License Agreement shall be deemed to create any relationship
 *    of agency, partnership, or joint venture between PSF and Licensee.  This License
 *    Agreement does not grant permission to use PSF trademarks or trade name in a
 *    trademark sense to endorse or promote products or services of Licensee, or any
 *    third party.
 *
 * 8. By copying, installing or otherwise using Python 3.10.0, Licensee agrees
 *    to be bound by the terms and conditions of this License Agreement.
 *
 * -----------------------------------------------------------------------------------
 *
 * Brief summary of changes compared to the original Python 3.10 source:
 *
 * - Inlined and refactored IEEE 754 float conversion routines
 * - Usage of stdbool for function return values and boolean parameters
 * - Renamed functions and structures for clarity
 * - Interface adapated to ucode C api
 * - Removed unused code
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <float.h>
#include <assert.h>

#include "ucode/module.h"

static uc_resource_type_t *struct_type;

typedef struct formatdef {
	char format;
	ssize_t size;
	ssize_t alignment;
	uc_value_t* (*unpack)(uc_vm_t *, const char *, const struct formatdef *);
	bool (*pack)(uc_vm_t *, char *, uc_value_t *, const struct formatdef *);
} formatdef_t;

typedef struct {
	const formatdef_t *fmtdef;
	ssize_t offset;
	ssize_t size;
	ssize_t repeat;
} formatcode_t;

typedef struct {
	size_t len;
	size_t size;
	size_t ncodes;
	formatcode_t codes[];
} formatstate_t;


/* Define various structs to figure out the alignments of types */

typedef struct { char c; short x; } st_short;
typedef struct { char c; int x; } st_int;
typedef struct { char c; long x; } st_long;
typedef struct { char c; float x; } st_float;
typedef struct { char c; double x; } st_double;
typedef struct { char c; void *x; } st_void_p;
typedef struct { char c; size_t x; } st_size_t;
typedef struct { char c; bool x; } st_bool;
typedef struct { char c; long long x; } s_long_long;

#define SHORT_ALIGN (sizeof(st_short) - sizeof(short))
#define INT_ALIGN (sizeof(st_int) - sizeof(int))
#define LONG_ALIGN (sizeof(st_long) - sizeof(long))
#define FLOAT_ALIGN (sizeof(st_float) - sizeof(float))
#define DOUBLE_ALIGN (sizeof(st_double) - sizeof(double))
#define VOID_P_ALIGN (sizeof(st_void_p) - sizeof(void *))
#define SIZE_T_ALIGN (sizeof(st_size_t) - sizeof(size_t))
#define BOOL_ALIGN (sizeof(st_bool) - sizeof(bool))
#define LONG_LONG_ALIGN (sizeof(s_long_long) - sizeof(long long))

#ifdef __powerc
#pragma options align=reset
#endif


static bool
ucv_as_long(uc_vm_t *vm, uc_value_t *v, long *p)
{
	char *s, *e;
	int64_t i;
	double d;
	long x;

	errno = 0;

	switch (ucv_type(v)) {
	case UC_INTEGER:
		i = ucv_int64_get(v);

		if (i < LONG_MIN || i > LONG_MAX)
			errno = ERANGE;

		x = (long)i;
		break;

	case UC_DOUBLE:
		d = ucv_double_get(v);
		x = (long)d;

		if (isnan(d) || d < (double)LONG_MIN || d > (double)LONG_MAX || d - x != 0)
			errno = ERANGE;

		break;

	case UC_BOOLEAN:
		x = (long)ucv_boolean_get(v);
		break;

	case UC_NULL:
		x = 0;
		break;

	case UC_STRING:
		s = ucv_string_get(v);
		x = strtol(s, &e, 0);

		if (e == s || *e != '\0')
			errno = EINVAL;

		break;

	default:
		errno = EINVAL;
		x = 0;
		break;
	}

	if (errno != 0) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			(errno == ERANGE)
				? "Argument out of range"
				: "Argument not convertible to number");

		return false;
	}

	*p = x;

	return true;
}

static bool
ucv_as_ulong(uc_vm_t *vm, uc_value_t *v, unsigned long *p)
{
	unsigned long x;
	char *s, *e;
	uint64_t i;
	double d;

	errno = 0;

	switch (ucv_type(v)) {
	case UC_INTEGER:
		i = ucv_uint64_get(v);

		if (i > ULONG_MAX)
			errno = ERANGE;

		x = (unsigned long)i;
		break;

	case UC_DOUBLE:
		d = ucv_double_get(v);
		x = (unsigned long)d;

		if (isnan(d) || d < 0 || d > (double)ULONG_MAX || d - x != 0)
			errno = ERANGE;

		break;

	case UC_BOOLEAN:
		x = (unsigned long)ucv_boolean_get(v);
		break;

	case UC_NULL:
		x = 0;
		break;

	case UC_STRING:
		s = ucv_string_get(v);
		x = strtoul(s, &e, 0);

		if (e == s || *e != '\0')
			errno = EINVAL;

		break;

	default:
		errno = EINVAL;
		x = 0;
		break;
	}

	if (errno != 0) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			(errno == ERANGE)
				? "Argument out of range"
				: "Argument not convertible to number");

		return false;
	}

	*p = x;

	return true;
}

static bool
ucv_as_longlong(uc_vm_t *vm, uc_value_t *v, long long *p)
{
	char *s, *e;
	long long x;
	int64_t i;
	double d;

	errno = 0;

	switch (ucv_type(v)) {
	case UC_INTEGER:
		i = ucv_int64_get(v);

		if (i < LLONG_MIN || i > LLONG_MAX)
			errno = ERANGE;

		x = (long long)i;
		break;

	case UC_DOUBLE:
		d = ucv_double_get(v);
		x = (long long)d;

		if (isnan(d) || d < (double)LLONG_MIN || d > (double)LLONG_MAX || d - x != 0)
			errno = ERANGE;

		break;

	case UC_BOOLEAN:
		x = (long long)ucv_boolean_get(v);
		break;

	case UC_NULL:
		x = 0;
		break;

	case UC_STRING:
		s = ucv_string_get(v);
		x = strtoll(s, &e, 0);

		if (e == s || *e != '\0')
			errno = EINVAL;

		break;

	default:
		errno = EINVAL;
		x = 0;
		break;
	}

	if (errno != 0) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			(errno == ERANGE)
				? "Argument out of range"
				: "Argument not convertible to number");

		return false;
	}

	*p = x;

	return true;
}

static bool
ucv_as_ulonglong(uc_vm_t *vm, uc_value_t *v, unsigned long long *p)
{
	unsigned long long x;
	char *s, *e;
	uint64_t i;
	double d;

	errno = 0;

	switch (ucv_type(v)) {
	case UC_INTEGER:
		i = ucv_uint64_get(v);

		if (i > ULLONG_MAX)
			errno = ERANGE;

		x = (unsigned long long)i;
		break;

	case UC_DOUBLE:
		d = ucv_double_get(v);
		x = (unsigned long long)d;

		if (isnan(d) || d < 0 || d > (double)ULLONG_MAX || d - x != 0)
			errno = ERANGE;

		break;

	case UC_BOOLEAN:
		x = (unsigned long long)ucv_boolean_get(v);
		break;

	case UC_NULL:
		x = 0;
		break;

	case UC_STRING:
		s = ucv_string_get(v);
		x = strtoull(s, &e, 0);

		if (e == s || *e != '\0')
			errno = EINVAL;

		break;

	default:
		errno = EINVAL;
		x = 0;
		break;
	}

	if (errno != 0) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			(errno == ERANGE)
				? "Argument out of range"
				: "Argument not convertible to number");

		return false;
	}

	*p = x;

	return true;
}

static bool
ucv_as_ssize_t(uc_vm_t *vm, uc_value_t *v, ssize_t *p)
{
	char *s, *e;
	int64_t i;
	ssize_t x;
	double d;

	errno = 0;

	switch (ucv_type(v)) {
	case UC_INTEGER:
		i = ucv_int64_get(v);

		if (i < -1 || i > SSIZE_MAX)
			errno = ERANGE;

		x = (ssize_t)i;
		break;

	case UC_DOUBLE:
		d = ucv_double_get(v);
		x = (ssize_t)d;

		if (isnan(d) || d < -1 || d > (double)SSIZE_MAX || d - x != 0)
			errno = ERANGE;

		break;

	case UC_BOOLEAN:
		x = (ssize_t)ucv_boolean_get(v);
		break;

	case UC_NULL:
		x = 0;
		break;

	case UC_STRING:
		s = ucv_string_get(v);
		i = strtoll(s, &e, 0);

		if (e == s || *e != '\0')
			errno = EINVAL;
		else if (i < -1 || i > SSIZE_MAX)
			errno = ERANGE;

		x = (ssize_t)i;
		break;

	default:
		errno = EINVAL;
		x = 0;
		break;
	}

	if (errno != 0) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			(errno == ERANGE)
				? "Argument out of range"
				: "Argument not convertible to number");

		return false;
	}

	*p = x;

	return true;
}

/* Same, but handling size_t */

static bool
ucv_as_size_t(uc_vm_t *vm, uc_value_t *v, size_t *p)
{
	char *s, *e;
	uint64_t i;
	double d;
	size_t x;

	errno = 0;

	switch (ucv_type(v)) {
	case UC_INTEGER:
		i = ucv_uint64_get(v);

		if (i > SIZE_MAX)
			errno = ERANGE;

		x = (size_t)i;
		break;

	case UC_DOUBLE:
		d = ucv_double_get(v);
		x = (size_t)d;

		if (isnan(d) || d < 0 || d > (double)SIZE_MAX || d - x != 0)
			errno = ERANGE;

		break;

	case UC_BOOLEAN:
		x = (size_t)ucv_boolean_get(v);
		break;

	case UC_NULL:
		x = 0;
		break;

	case UC_STRING:
		s = ucv_string_get(v);
		i = strtoull(s, &e, 0);

		if (e == s || *e != '\0')
			errno = EINVAL;
		else if (i > SIZE_MAX)
			errno = ERANGE;

		x = (size_t)i;
		break;

	default:
		errno = EINVAL;
		x = 0;
		break;
	}

	if (errno != 0) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			(errno == ERANGE)
				? "Argument out of range"
				: "Argument not convertible to number");

		return false;
	}

	*p = x;

	return true;
}

static bool
ucv_as_double(uc_vm_t *vm, uc_value_t *v, double *p)
{
	char *s, *e;
	int64_t i;
	double x;

	errno = 0;

	switch (ucv_type(v)) {
	case UC_INTEGER:
		i = ucv_int64_get(v);

		if (errno == 0) {
			if (i < -DBL_MAX || i > DBL_MAX)
				errno = ERANGE;
		}

		x = (double)i;
		break;

	case UC_DOUBLE:
		x = ucv_double_get(v);
		break;

	case UC_BOOLEAN:
		x = (double)ucv_boolean_get(v);
		break;

	case UC_NULL:
		x = 0.0;
		break;

	case UC_STRING:
		s = ucv_string_get(v);
		x = strtod(s, &e);

		if (e == s || *e != '\0')
			errno = EINVAL;

		break;

	default:
		errno = EINVAL;
		x = 0.0;
		break;
	}

	if (errno != 0) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			(errno == ERANGE)
				? "Argument out of range"
				: "Argument not convertible to number");

		return false;
	}

	*p = x;

	return true;
}


/* Floating point helpers */

static bool
double_pack16(double d, char *buf, bool little_endian)
{
	int32_t exponent = 0;
	uint16_t bits = 0;
	bool sign = false;
	double fraction;
	uint8_t *p;

	if (d == 0.0) {
		sign = (copysign(1.0, d) == -1.0);
	}
	else if (isnan(d)) {
		sign = (copysign(1.0, d) == -1.0);
		exponent = 0x1f;
		bits = 512;
	}
	else if (!isfinite(d)) {
		sign = (d < 0.0);
		exponent = 0x1f;
	}
	else {
		if (d < 0.0) {
			sign = true;
			d = -d;
		}

		fraction = frexp(d, &exponent);

		assert(fraction >= 0.5 && fraction < 1.0);

		fraction *= 2.0;
		exponent--;

		if (exponent >= 16) {
			errno = ERANGE;

			return false;
		}
		else if (exponent < -25) {
			fraction = 0.0;
			exponent = 0;
		}
		else if (exponent < -14) {
			fraction = ldexp(fraction, 14 + exponent);
			exponent = 0;
		}
		else {
			fraction -= 1.0;
			exponent += 15;
		}

		fraction *= 1024.0;
		bits = (uint16_t)fraction;

		assert(bits < 1024);
		assert(exponent < 31);

		if ((fraction - bits > 0.5) || ((fraction - bits == 0.5) && (bits % 2))) {
			if (++bits == 1024) {
				bits = 0;

				if (++exponent == 31) {
					errno = ERANGE;

					return false;
				}
			}
		}
	}

	bits |= (exponent << 10) | (sign << 15);

	p = (uint8_t *)buf + little_endian;
	*p = (bits >> 8) & 0xff;

	p += (little_endian ? -1 : 1);
	*p = bits & 0xff;

	return true;
}

static bool
double_pack32(double d, char *buf, bool little_endian)
{
	int8_t step = little_endian ? -1 : 1;
	int32_t exponent = 0;
	uint32_t bits = 0;
	bool sign = false;
	double fraction;
	uint8_t *p;

	if (d == 0.0) {
		sign = (copysign(1.0, d) == -1.0);
	}
	else if (isnan(d)) {
		sign = (copysign(1.0, d) == -1.0);
		exponent = 0xff;
		bits = 0x7fffff;
	}
	else if (!isfinite(d)) {
		sign = (d < 0.0);
		exponent = 0xff;
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

		if (exponent >= 128) {
			errno = ERANGE;

			return false;
		}
		else if (exponent < -126) {
			fraction = ldexp(fraction, 126 + exponent);
			exponent = 0;
		}
		else if (exponent != 0 || fraction != 0.0) {
			fraction -= 1.0;
			exponent += 127;
		}

		fraction *= 8388608.0;
		bits = (uint32_t)(fraction + 0.5);

		assert(bits <= 8388608);

		if (bits >> 23) {
			bits = 0;

			if (++exponent >= 255) {
				errno = ERANGE;

				return false;
			}
		}
	}

	p = (uint8_t *)buf + (little_endian ? 3 : 0);
	*p = (sign << 7) | (exponent >> 1);

	p += step;
	*p = ((exponent & 1) << 7) | (bits >> 16);

	p += step;
	*p = (bits >> 8) & 0xff;

	p += step;
	*p = bits & 0xff;

	return true;
}

static bool
double_pack64(double d, char *buf, bool little_endian)
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

static double
double_unpack16(const char *buf, bool little_endian)
{
	uint32_t fraction;
	int32_t exponent;
	uint8_t *p;
	bool sign;
	double d;

	p = (uint8_t *)buf + little_endian;
	sign = (*p >> 7) & 1;
	exponent = (*p & 0x7c) >> 2;
	fraction = (*p & 0x03) << 8;

	p += little_endian ? -1 : 1;
	fraction |= *p;

	if (exponent == 0x1f) {
		if (fraction == 0)
			return sign ? -INFINITY : INFINITY;
		else
			return sign ? -NAN : NAN;
	}

	d = (double)fraction / 1024.0;

	if (exponent == 0) {
		exponent = -14;
	}
	else {
		exponent -= 15;
		d += 1.0;
	}

	d = ldexp(d, exponent);

	return sign ? -d : d;
}

static double
double_unpack32(const char *buf, bool little_endian)
{
	int8_t step = little_endian ? -1 : 1;
	uint32_t fraction;
	int32_t exponent;
	uint8_t *p;
	bool sign;
	double d;

	p = (uint8_t *)buf + (little_endian ? 3 : 0);
	sign = (*p >> 7) & 1;
	exponent = (*p & 0x7f) << 1;

	p += step;
	exponent |= (*p >> 7) & 1;
	fraction = (*p & 0x7f) << 16;

	p += step;
	fraction |= *p << 8;

	p += step;
	fraction |= *p;

	if (exponent == 0xff) {
		if (fraction == 0)
			return sign ? -INFINITY : INFINITY;
		else
			return sign ? -NAN : NAN;
	}

	d = (double)fraction / 8388608.0;

	if (exponent == 0) {
		exponent = -126;
	}
	else {
		exponent -= 127;
		d += 1.0;
	}

	d = ldexp(d, exponent);

	return sign ? -d : d;
}


static double
double_unpack64(const char *buf, bool little_endian)
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

static bool
range_exception(uc_vm_t *vm, const formatdef_t *f, bool is_unsigned)
{
	/* ulargest is the largest unsigned value with f->size bytes.
	 * Note that the simpler:
	 *	 ((size_t)1 << (f->size * 8)) - 1
	 * doesn't work when f->size == sizeof(size_t) because C doesn't
	 * define what happens when a left shift count is >= the number of
	 * bits in the integer being shifted; e.g., on some boxes it doesn't
	 * shift at all when they're equal.
	 */
	const size_t ulargest = (size_t)-1 >> ((sizeof(size_t) - f->size)*8);

	assert(f->size >= 1 && f->size <= (ssize_t)sizeof(size_t));

	if (is_unsigned) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			"Format '%c' requires numeric argument between 0 and %zu",
			f->format,
			ulargest);
	}
	else {
		const ssize_t largest = (ssize_t)(ulargest >> 1);

		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			"Format '%c' requires numeric argument between %zd and %zd",
			f->format,
			~ largest,
			largest);
	}

	return false;
}


/* Native mode routines. ****************************************************/

static uc_value_t *
native_unpack_char(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	return ucv_string_new_length(p, 1);
}

static uc_value_t *
native_unpack_byte(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	return ucv_int64_new(*(signed char *)p);
}

static uc_value_t *
native_unpack_ubyte(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	return ucv_uint64_new(*(unsigned char *)p);
}

static uc_value_t *
native_unpack_short(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	short x = 0;

	memcpy(&x, p, sizeof(x));

	return ucv_int64_new(x);
}

static uc_value_t *
native_unpack_ushort(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	unsigned short x = 0;

	memcpy(&x, p, sizeof(x));

	return ucv_uint64_new(x);
}

static uc_value_t *
native_unpack_int(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	int x = 0;

	memcpy(&x, p, sizeof(x));

	return ucv_int64_new(x);
}

static uc_value_t *
native_unpack_uint(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	unsigned int x = 0;

	memcpy(&x, p, sizeof(x));

	return ucv_uint64_new(x);
}

static uc_value_t *
native_unpack_long(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	long x = 0;

	memcpy(&x, p, sizeof(x));

	return ucv_int64_new(x);
}

static uc_value_t *
native_unpack_ulong(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	unsigned long x = 0;

	memcpy(&x, p, sizeof(x));

	return ucv_uint64_new(x);
}

static uc_value_t *
native_unpack_ssize_t(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	ssize_t x = 0;

	memcpy(&x, p, sizeof(x));

	return ucv_int64_new(x);
}

static uc_value_t *
native_unpack_size_t(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	size_t x = 0;

	memcpy(&x, p, sizeof(x));

	return ucv_uint64_new(x);
}

static uc_value_t *
native_unpack_longlong(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	long long x = 0;

	memcpy(&x, p, sizeof(x));

	return ucv_int64_new(x);
}

static uc_value_t *
native_unpack_ulonglong(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	unsigned long long x = 0;

	memcpy(&x, p, sizeof(x));

	return ucv_uint64_new(x);
}

static uc_value_t *
native_unpack_bool(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	bool x = false;

	memcpy(&x, p, sizeof(x));

	return ucv_boolean_new(x != 0);
}


static uc_value_t *
native_unpack_halffloat(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	return ucv_double_new(double_unpack16(p, true));
#else
	return ucv_double_new(double_unpack16(p, false));
#endif
}

static uc_value_t *
native_unpack_float(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	float x = 0.0;

	memcpy(&x, p, sizeof(x));

	return ucv_double_new(x);
}

static uc_value_t *
native_unpack_double(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	double x = 0.0;

	memcpy(&x, p, sizeof(x));

	return ucv_double_new(x);
}

static uc_value_t *
native_unpack_void_p(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	void *x = NULL;

	memcpy(&x, p, sizeof(x));

	return ucv_int64_new((intptr_t)x);
}

static bool
native_pack_byte(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	long x = 0;

	if (!ucv_as_long(vm, v, &x))
		return false;

	if (x < -128 || x > 127) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			"Byte format requires numeric value between -128 and 127");

		return false;
	}

	*p = (char)x;

	return true;
}

static bool
native_pack_ubyte(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	long x = 0;

	if (!ucv_as_long(vm, v, &x))
		return false;

	if (x < 0 || x > 255) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			"Unsigned byte format requires numeric value between 0 and 255");

		return false;
	}

	*(unsigned char *)p = (unsigned char)x;

	return true;
}

static bool
native_pack_char(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	char *s = NULL;

	if (ucv_type(v) == UC_STRING) {
		s = ucv_string_get(v);
		*p = *s;
	}
	else {
		s = ucv_to_string(vm, v);
		*p = *s;
		free(s);
	}

	return true;
}

static bool
native_pack_short(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	long x = 0;
	short y = 0;

	if (!ucv_as_long(vm, v, &x))
		return false;

	if (x < SHRT_MIN || x > SHRT_MAX) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			"Short format requires numeric value between %d and %d",
			(int)SHRT_MIN, (int)SHRT_MAX);

		return false;
	}

	y = (short)x;
	memcpy(p, &y, sizeof(y));

	return true;
}

static bool
native_pack_ushort(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	unsigned short y = 0;
	long x = 0;

	if (!ucv_as_long(vm, v, &x))
		return false;

	if (x < 0 || x > USHRT_MAX) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			"Unsigned short format requires numeric value between 0 and %u",
			(unsigned int)USHRT_MAX);

		return false;
	}

	y = (unsigned short)x;
	memcpy(p, &y, sizeof(y));

	return true;
}

static bool
native_pack_int(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	long x = 0;
	int y = 0;

	if (!ucv_as_long(vm, v, &x))
		return false;

	if (sizeof(long) > sizeof(int)) {
		if ((x < ((long)INT_MIN)) || (x > ((long)INT_MAX)))
			return range_exception(vm, f, false);
	}

	y = (int)x;
	memcpy(p, &y, sizeof(y));

	return true;
}

static bool
native_pack_uint(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	unsigned long x = 0;
	unsigned int y = 0;

	if (!ucv_as_ulong(vm, v, &x))
		return false;

	if (sizeof(long) > sizeof(int)) {
		if (x > ((unsigned long)UINT_MAX))
			return range_exception(vm, f, true);
	}

	y = (unsigned int)x;
	memcpy(p, &y, sizeof(y));

	return true;
}

static bool
native_pack_long(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	long x = 0;

	if (!ucv_as_long(vm, v, &x))
		return false;

	memcpy(p, &x, sizeof(x));

	return true;
}

static bool
native_pack_ulong(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	unsigned long x = 0;

	if (!ucv_as_ulong(vm, v, &x))
		return false;

	memcpy(p, &x, sizeof(x));

	return true;
}

static bool
native_pack_ssize_t(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	ssize_t x = 0;

	if (!ucv_as_ssize_t(vm, v, &x))
		return false;

	memcpy(p, &x, sizeof(x));

	return true;
}

static bool
native_pack_size_t(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	size_t x = 0;

	if (!ucv_as_size_t(vm, v, &x))
		return false;

	memcpy(p, &x, sizeof(x));

	return true;
}

static bool
native_pack_longlong(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	long long x = 0;

	if (!ucv_as_longlong(vm, v, &x))
		return false;

	memcpy(p, &x, sizeof(x));

	return true;
}

static bool
native_pack_ulonglong(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	unsigned long long x = 0;

	if (!ucv_as_ulonglong(vm, v, &x))
		return false;

	memcpy(p, &x, sizeof(x));

	return true;
}


static bool
native_pack_bool(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	bool x = 0;

	x = ucv_is_truish(v);

	memcpy(p, &x, sizeof(x));

	return true;
}

static bool
native_pack_halffloat(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	double x;

	if (!ucv_as_double(vm, v, &x))
		return false;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	return double_pack16(x, p, true);
#else
	return double_pack16(x, p, false);
#endif
}

static bool
native_pack_float(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	double d = 0.0;
	float x = 0.0;

	if (!ucv_as_double(vm, v, &d))
		return false;

	x = (float)d;
	memcpy(p, &x, sizeof(x));

	return true;
}

static bool
native_pack_double(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	double x = 0.0;

	if (!ucv_as_double(vm, v, &x))
		return false;

	memcpy(p, &x, sizeof(x));

	return true;
}

static bool
native_pack_void_p(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	long long int i = 0;
	void *x = NULL;

	if (!ucv_as_longlong(vm, v, &i))
		return false;

	x = (void *)(intptr_t)i;
	memcpy(p, &x, sizeof(x));

	return true;
}

static const formatdef_t native_endian_table[] = {
	{ 'x', sizeof(char), 0, NULL, NULL },
	{ 'b', sizeof(char), 0, native_unpack_byte, native_pack_byte },
	{ 'B', sizeof(char), 0, native_unpack_ubyte, native_pack_ubyte },
	{ 'c', sizeof(char), 0, native_unpack_char, native_pack_char },
	{ 's', sizeof(char), 0, NULL, NULL },
	{ 'p', sizeof(char), 0, NULL, NULL },
	{ 'h', sizeof(short), SHORT_ALIGN, native_unpack_short, native_pack_short },
	{ 'H', sizeof(short), SHORT_ALIGN, native_unpack_ushort, native_pack_ushort },
	{ 'i', sizeof(int),	INT_ALIGN, native_unpack_int, native_pack_int },
	{ 'I', sizeof(int),	INT_ALIGN, native_unpack_uint, native_pack_uint },
	{ 'l', sizeof(long), LONG_ALIGN, native_unpack_long, native_pack_long },
	{ 'L', sizeof(long), LONG_ALIGN, native_unpack_ulong, native_pack_ulong },
	{ 'n', sizeof(size_t), SIZE_T_ALIGN, native_unpack_ssize_t, native_pack_ssize_t },
	{ 'N', sizeof(size_t), SIZE_T_ALIGN, native_unpack_size_t, native_pack_size_t },
	{ 'q', sizeof(long long), LONG_LONG_ALIGN, native_unpack_longlong, native_pack_longlong },
	{ 'Q', sizeof(long long), LONG_LONG_ALIGN, native_unpack_ulonglong,native_pack_ulonglong },
	{ '?', sizeof(bool), BOOL_ALIGN, native_unpack_bool, native_pack_bool },
	{ 'e', sizeof(short), SHORT_ALIGN, native_unpack_halffloat, native_pack_halffloat },
	{ 'f', sizeof(float), FLOAT_ALIGN, native_unpack_float, native_pack_float },
	{ 'd', sizeof(double), DOUBLE_ALIGN, native_unpack_double, native_pack_double },
	{ 'P', sizeof(void *), VOID_P_ALIGN, native_unpack_void_p, native_pack_void_p },
	{ 0 }
};


/* Big-endian routines. *****************************************************/

static uc_value_t *
be_unpack_int(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	const unsigned char *bytes = (const unsigned char *)p;
	ssize_t i = f->size;
	long x = 0;

	do {
		x = (x<<8) | *bytes++;
	} while (--i > 0);

	/* Extend the sign bit. */
	if ((ssize_t)sizeof(long) > f->size)
		x |= -(x & (1L << ((8 * f->size) - 1)));

	return ucv_int64_new(x);
}

static uc_value_t *
be_unpack_uint(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	const unsigned char *bytes = (const unsigned char *)p;
	ssize_t i = f->size;
	unsigned long x = 0;

	do {
		x = (x<<8) | *bytes++;
	} while (--i > 0);

	return ucv_uint64_new(x);
}

static uc_value_t *
be_unpack_longlong(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	const unsigned char *bytes = (const unsigned char *)p;
	ssize_t i = f->size;
	long long x = 0;

	do {
		x = (x<<8) | *bytes++;
	} while (--i > 0);

	/* Extend the sign bit. */
	if ((ssize_t)sizeof(long long) > f->size)
		x |= -(x & ((long long)1 << ((8 * f->size) - 1)));

	return ucv_int64_new(x);
}

static uc_value_t *
be_unpack_ulonglong(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	const unsigned char *bytes = (const unsigned char *)p;
	unsigned long long x = 0;
	ssize_t i = f->size;

	do {
		x = (x<<8) | *bytes++;
	} while (--i > 0);

	return ucv_uint64_new(x);
}

static uc_value_t *
be_unpack_halffloat(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	return ucv_double_new(double_unpack16(p, false));
}

static uc_value_t *
be_unpack_float(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	return ucv_double_new(double_unpack32(p, false));
}

static uc_value_t *
be_unpack_double(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	return ucv_double_new(double_unpack64(p, false));
}

static uc_value_t *
be_unpack_bool(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	return ucv_boolean_new(*p != 0);
}

static bool
be_pack_int(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	unsigned char *q = (unsigned char *)p;
	ssize_t i = 0;
	long x = 0;

	if (!ucv_as_long(vm, v, &x))
		return false;

	i = f->size;

	if (i != sizeof(long)) {
		if ((i == 2) && (x < -32768 || x > 32767))
			return range_exception(vm, f, false);
#if UINT_MAX < ULONG_MAX
		else if ((i == 4) && (x < -2147483648L || x > 2147483647L))
			return range_exception(vm, f, false);
#endif
	}

	do {
		q[--i] = (unsigned char)(x & 0xffL);
		x >>= 8;
	} while (i > 0);

	return true;
}

static bool
be_pack_uint(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	unsigned char *q = (unsigned char *)p;
	unsigned long x = 0;
	ssize_t i = 0;

	if (!ucv_as_ulong(vm, v, &x))
		return false;

	i = f->size;

	if (i != sizeof(long)) {
		unsigned long maxint = 1;
		maxint <<= (unsigned long)(i * 8);
		if (x >= maxint)
			return range_exception(vm, f, true);
	}

	do {
		q[--i] = (unsigned char)(x & 0xffUL);
		x >>= 8;
	} while (i > 0);

	return true;
}

static bool
be_pack_longlong(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	unsigned char *q = (unsigned char *)p;
	long long x = 0;
	ssize_t i = 0;

	if (!ucv_as_longlong(vm, v, &x))
		return false;

	i = f->size;

	do {
		q[--i] = (unsigned char)(x & 0xffL);
		x >>= 8;
	} while (i > 0);

	return true;
}

static bool
be_pack_ulonglong(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	unsigned char *q = (unsigned char *)p;
	unsigned long long x = 0;
	ssize_t i = 0;

	if (!ucv_as_ulonglong(vm, v, &x))
		return false;

	i = f->size;

	do {
		q[--i] = (unsigned char)(x & 0xffUL);
		x >>= 8;
	} while (i > 0);

	return true;
}

static bool
be_pack_halffloat(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	double x = 0.0;

	if (!ucv_as_double(vm, v, &x))
		return false;

	return double_pack16(x, p, false);
}

static bool
be_pack_float(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	double x = 0.0;

	if (!ucv_as_double(vm, v, &x))
		return false;

	if (!double_pack32(x, p, 0)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Argument out of range");

		return false;
	}

	return true;
}

static bool
be_pack_double(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	double x = 0.0;

	if (!ucv_as_double(vm, v, &x))
		return false;

	if (!double_pack64(x, p, 0)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Argument out of range");

		return false;
	}

	return true;
}

static bool
be_pack_bool(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	*p = (char)ucv_is_truish(v);

	return true;
}

static formatdef_t big_endian_table[] = {
	{ 'x', 1, 0, NULL, NULL },
	{ 'b', 1, 0, native_unpack_byte, native_pack_byte },
	{ 'B', 1, 0, native_unpack_ubyte, native_pack_ubyte },
	{ 'c', 1, 0, native_unpack_char, native_pack_char },
	{ 's', 1, 0, NULL, NULL },
	{ 'p', 1, 0, NULL, NULL },
	{ 'h', 2, 0, be_unpack_int, be_pack_int },
	{ 'H', 2, 0, be_unpack_uint, be_pack_uint },
	{ 'i', 4, 0, be_unpack_int, be_pack_int },
	{ 'I', 4, 0, be_unpack_uint, be_pack_uint },
	{ 'l', 4, 0, be_unpack_int, be_pack_int },
	{ 'L', 4, 0, be_unpack_uint, be_pack_uint },
	{ 'q', 8, 0, be_unpack_longlong, be_pack_longlong },
	{ 'Q', 8, 0, be_unpack_ulonglong, be_pack_ulonglong },
	{ '?', 1, 0, be_unpack_bool, be_pack_bool },
	{ 'e', 2, 0, be_unpack_halffloat, be_pack_halffloat },
	{ 'f', 4, 0, be_unpack_float, be_pack_float },
	{ 'd', 8, 0, be_unpack_double, be_pack_double },
	{ 0 }
};


/* Little-endian routines. *****************************************************/

static uc_value_t *
le_unpack_int(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	const unsigned char *bytes = (const unsigned char *)p;
	ssize_t i = f->size;
	long x = 0;

	do {
		x = (x<<8) | bytes[--i];
	} while (i > 0);

	/* Extend the sign bit. */
	if ((ssize_t)sizeof(long) > f->size)
		x |= -(x & (1L << ((8 * f->size) - 1)));

	return ucv_int64_new(x);
}

static uc_value_t *
le_unpack_uint(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	const unsigned char *bytes = (const unsigned char *)p;
	ssize_t i = f->size;
	unsigned long x = 0;

	do {
		x = (x<<8) | bytes[--i];
	} while (i > 0);

	return ucv_uint64_new(x);
}

static uc_value_t *
le_unpack_longlong(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	const unsigned char *bytes = (const unsigned char *)p;
	ssize_t i = f->size;
	long long x = 0;

	do {
		x = (x<<8) | bytes[--i];
	} while (i > 0);

	/* Extend the sign bit. */
	if ((ssize_t)sizeof(long long) > f->size)
		x |= -(x & ((long long)1 << ((8 * f->size) - 1)));

	return ucv_int64_new(x);
}

static uc_value_t *
le_unpack_ulonglong(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	const unsigned char *bytes = (const unsigned char *)p;
	unsigned long long x = 0;
	ssize_t i = f->size;

	do {
		x = (x<<8) | bytes[--i];
	} while (i > 0);

	return ucv_uint64_new(x);
}

static uc_value_t *
le_unpack_halffloat(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	return ucv_double_new(double_unpack16(p, true));
}

static uc_value_t *
le_unpack_float(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	return ucv_double_new(double_unpack32(p, true));
}

static uc_value_t *
le_unpack_double(uc_vm_t *vm, const char *p, const formatdef_t *f)
{
	return ucv_double_new(double_unpack64(p, true));
}

static bool
le_pack_int(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	unsigned char *q = (unsigned char *)p;
	ssize_t i = 0;
	long x = 0;

	if (!ucv_as_long(vm, v, &x))
		return false;

	i = f->size;

	if (i != sizeof(long)) {
		if ((i == 2) && (x < -32768 || x > 32767))
			return range_exception(vm, f, false);
#if UINT_MAX < ULONG_MAX
		else if ((i == 4) && (x < -2147483648L || x > 2147483647L))
			return range_exception(vm, f, false);
#endif
	}

	do {
		*q++ = (unsigned char)(x & 0xffL);
		x >>= 8;
	} while (--i > 0);

	return true;
}

static bool
le_pack_uint(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	unsigned char *q = (unsigned char *)p;
	unsigned long x = 0;
	ssize_t i = 0;

	if (!ucv_as_ulong(vm, v, &x))
		return false;

	i = f->size;

	if (i != sizeof(long)) {
		unsigned long maxint = 1;
		maxint <<= (unsigned long)(i * 8);

		if (x >= maxint)
			return range_exception(vm, f, true);
	}

	do {
		*q++ = (unsigned char)(x & 0xffUL);
		x >>= 8;
	} while (--i > 0);

	return true;
}

static bool
le_pack_longlong(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	unsigned char *q = (unsigned char *)p;
	long long x = 0;
	ssize_t i = 0;

	if (!ucv_as_longlong(vm, v, &x))
		return false;

	i = f->size;

	do {
		*q++ = (unsigned char)(x & 0xffL);
		x >>= 8;
	} while (--i > 0);

	return true;
}

static bool
le_pack_ulonglong(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	unsigned char *q = (unsigned char *)p;
	unsigned long long x = 0;
	ssize_t i = 0;

	if (!ucv_as_ulonglong(vm, v, &x))
		return false;

	i = f->size;

	do {
		*q++ = (unsigned char)(x & 0xffUL);
		x >>= 8;
	} while (--i > 0);

	return true;
}

static bool
le_pack_halffloat(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	double x = 0.0;

	if (!ucv_as_double(vm, v, &x))
		return false;

	return double_pack16(x, p, true);
}

static bool
le_pack_float(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	double x = 0.0;

	if (!ucv_as_double(vm, v, &x))
		return false;

	if (!double_pack32(x, p, 1)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Argument out of range");

		return false;
	}

	return true;
}

static bool
le_pack_double(uc_vm_t *vm, char *p, uc_value_t *v, const formatdef_t *f)
{
	double x = 0.0;

	if (!ucv_as_double(vm, v, &x))
		return false;

	if (!double_pack64(x, p, 1)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Argument out of range");

		return false;
	}

	return true;
}

static formatdef_t little_endian_table[] = {
	{ 'x', 1, 0, NULL, NULL },
	{ 'b', 1, 0, native_unpack_byte, native_pack_byte },
	{ 'B', 1, 0, native_unpack_ubyte, native_pack_ubyte },
	{ 'c', 1, 0, native_unpack_char, native_pack_char },
	{ 's', 1, 0, NULL, NULL },
	{ 'p', 1, 0, NULL, NULL },
	{ 'h', 2, 0, le_unpack_int, le_pack_int },
	{ 'H', 2, 0, le_unpack_uint, le_pack_uint },
	{ 'i', 4, 0, le_unpack_int, le_pack_int },
	{ 'I', 4, 0, le_unpack_uint, le_pack_uint },
	{ 'l', 4, 0, le_unpack_int, le_pack_int },
	{ 'L', 4, 0, le_unpack_uint, le_pack_uint },
	{ 'q', 8, 0, le_unpack_longlong, le_pack_longlong },
	{ 'Q', 8, 0, le_unpack_ulonglong, le_pack_ulonglong },
	{ '?', 1, 0, be_unpack_bool, be_pack_bool },
	{ 'e', 2, 0, le_unpack_halffloat, le_pack_halffloat },
	{ 'f', 4, 0, le_unpack_float, le_pack_float },
	{ 'd', 8, 0, le_unpack_double, le_pack_double },
	{ 0 }
};


static const formatdef_t *
select_format_table(const char **pfmt)
{
	const char *fmt = (*pfmt)++; /* May be backed out of later */

	switch (*fmt) {
	case '<':
		return little_endian_table;

	case '>':
	case '!': /* Network byte order is big-endian */
		return big_endian_table;

	case '=':  /* Host byte order -- different from native in alignment! */
#if __BYTE_ORDER == __LITTLE_ENDIAN
		return little_endian_table;
#else
		return big_endian_table;
#endif

	default:
		--*pfmt; /* Back out of pointer increment */
		/* Fall through */

	case '@':
		return native_endian_table;
	}
}


/* Get the table entry for a format code */

static const formatdef_t *
lookup_table_entry(uc_vm_t *vm, int c, const formatdef_t *table)
{
	for (; table->format != '\0'; table++) {
		if (table->format == c) {
			return table;
		}
	}

	uc_vm_raise_exception(vm, EXCEPTION_TYPE,
		"Unrecognized character '%c' in struct format",
		c);

	return NULL;
}


/* Align a size according to a format code.  Return -1 on overflow. */

static ssize_t
align_for_entry(ssize_t size, const formatdef_t *e)
{
	ssize_t extra;

	if (e->alignment && size > 0) {
		extra = (e->alignment - 1) - (size - 1) % (e->alignment);

		if (extra > SSIZE_MAX - size)
			return -1;

		size += extra;
	}

	return size;
}


static void
optimize_functions(void)
{
	/* Check endian and swap in faster functions */
	const formatdef_t *native = native_endian_table;
	formatdef_t *other, *ptr;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	other = little_endian_table;
#else
	other = big_endian_table;
#endif

	/* Scan through the native table, find a matching
	   entry in the endian table and swap in the
	   native implementations whenever possible
	   (64-bit platforms may not have "standard" sizes) */
	while (native->format != '\0' && other->format != '\0') {
		ptr = other;

		while (ptr->format != '\0') {
			if (ptr->format == native->format) {
				/* Match faster when formats are
				   listed in the same order */
				if (ptr == other)
					other++;

				/* Only use the trick if the
				   size matches */
				if (ptr->size != native->size)
					break;

				/* Skip float and double, could be
				   "unknown" float format */
				if (ptr->format == 'd' || ptr->format == 'f')
					break;

				/* Skip bool, semantics are different for standard size */
				if (ptr->format == '?')
					break;

				ptr->pack = native->pack;
				ptr->unpack = native->unpack;
				break;
			}

			ptr++;
		}

		native++;
	}
}

static formatstate_t *
parse_format(uc_vm_t *vm, uc_value_t *fmtval)
{
	ssize_t size, len, num, itemsize;
	const formatdef_t *e, *f;
	const char *fmt, *s;
	formatstate_t *state;
	formatcode_t *codes;
	size_t ncodes;
	char c;

	if (ucv_type(fmtval) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			"Format value not a string");

		return NULL;
	}

	fmt = ucv_string_get(fmtval);

	if (strlen(fmt) != ucv_string_length(fmtval)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			"Format string contains embedded null character");

		return NULL;
	}

	f = select_format_table(&fmt);

	s = fmt;
	size = 0;
	len = 0;
	ncodes = 0;

	while ((c = *s++) != '\0') {
		if (isspace(c))
			continue;

		if ('0' <= c && c <= '9') {
			num = c - '0';

			while ('0' <= (c = *s++) && c <= '9') {
				/* overflow-safe version of
				   if (num*10 + (c - '0') > SSIZE_MAX) { ... } */
				if (num >= SSIZE_MAX / 10 && (
						num > SSIZE_MAX / 10 ||
						(c - '0') > SSIZE_MAX % 10))
					goto overflow;

				num = num*10 + (c - '0');
			}

			if (c == '\0') {
				uc_vm_raise_exception(vm, EXCEPTION_TYPE,
					"Format string contains repeat count given without format specifier");

				return NULL;
			}
		}
		else
			num = 1;

		e = lookup_table_entry(vm, c, f);

		if (e == NULL)
			return NULL;

		switch (c) {
		case 's': /* fall through */
		case 'p':
			len++;
			ncodes++;
			break;

		case 'x':
			break;

		default:
			len += num;

			if (num)
				ncodes++;

			break;
		}

		itemsize = e->size;
		size = align_for_entry(size, e);

		if (size == -1)
			goto overflow;

		/* if (size + num * itemsize > SSIZE_MAX) { ... } */
		if (num > (SSIZE_MAX - size) / itemsize)
			goto overflow;

		size += num * itemsize;
	}

	/* check for overflow */
	if ((ncodes + 1) > ((size_t)SSIZE_MAX / sizeof(formatcode_t))) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Out of memory");

		return NULL;
	}

	state = xalloc(sizeof(*state) + ncodes * sizeof(formatcode_t));
	state->len = len;
	state->size = size;
	state->ncodes = ncodes;

	codes = state->codes;

	s = fmt;
	size = 0;

	while ((c = *s++) != '\0') {
		if (isspace(c))
			continue;

		if ('0' <= c && c <= '9') {
			num = c - '0';

			while ('0' <= (c = *s++) && c <= '9')
				num = num*10 + (c - '0');
		}
		else
			num = 1;

		e = lookup_table_entry(vm, c, f);

		if (e == NULL)
			continue;

		size = align_for_entry(size, e);

		if (c == 's' || c == 'p') {
			codes->offset = size;
			codes->size = num;
			codes->fmtdef = e;
			codes->repeat = 1;
			codes++;
			size += num;
		}
		else if (c == 'x') {
			size += num;
		}
		else if (num) {
			codes->offset = size;
			codes->size = e->size;
			codes->fmtdef = e;
			codes->repeat = num;
			codes++;
			size += e->size * num;
		}
	}

	return state;

overflow:
  	uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
  		"Total struct size too long");

	return NULL;
}

static uc_value_t *
uc_pack_common(uc_vm_t *vm, size_t nargs, formatstate_t *state, size_t argoff)
{
	formatcode_t *code;
	uc_string_t *buf;
	size_t ncode;

	buf = xalloc(sizeof(*buf) + state->size + 1);
	buf->header.type = UC_STRING;
	buf->header.refcount = 1;
	buf->length = state->size;

	for (ncode = 0, code = &state->codes[0];
	     ncode < state->ncodes;
	     code = &state->codes[++ncode]) {
		const formatdef_t *e = code->fmtdef;
		char *res = buf->str + code->offset;
		ssize_t j = code->repeat;

		while (j--) {
			uc_value_t *v = uc_fn_arg(argoff++);

			if (e->format == 's') {
				ssize_t n;
				const void *p;

				if (ucv_type(v) != UC_STRING) {
					uc_vm_raise_exception(vm, EXCEPTION_TYPE,
						"Argument for 's' must be a string");

					goto err;
				}

				n = ucv_string_length(v);
				p = ucv_string_get(v);

				if (n > code->size)
					n = code->size;

				if (n > 0)
					memcpy(res, p, n);
			}
			else if (e->format == 'p') {
				ssize_t n;
				const void *p;

				if (ucv_type(v) != UC_STRING) {
					uc_vm_raise_exception(vm, EXCEPTION_TYPE,
						"Argument for 's' must be a string");

					goto err;
				}

				n = ucv_string_length(v);
				p = ucv_string_get(v);

				if (n > (code->size - 1))
					n = code->size - 1;

				if (n > 0)
					memcpy(res + 1, p, n);

				if (n > 255)
					n = 255;

				*res = (unsigned char)n;
			}
			else {
				if (!e->pack(vm, res, v, e))
					goto err;
			}

			res += code->size;
		}
	}

	return &buf->header;

err:
	free(buf);

	return NULL;
}

static uc_value_t *
uc_unpack_common(uc_vm_t *vm, size_t nargs, formatstate_t *state, size_t argoff)
{
	uc_value_t *bufval = uc_fn_arg(argoff);
	const char *startfrom = NULL;
	uc_value_t *result;
	formatcode_t *code;
	size_t ncode = 0;

	if (ucv_type(bufval) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			"Buffer value not a string");

		return NULL;
	}

	startfrom = ucv_string_get(bufval);
	result = ucv_array_new(vm);

	for (ncode = 0, code = &state->codes[0];
	     ncode < state->ncodes;
	     code = &state->codes[++ncode]) {
		const formatdef_t *e = code->fmtdef;
		const char *res = startfrom + code->offset;
		ssize_t j = code->repeat;

		while (j--) {
			uc_value_t *v = NULL;

			if (e->format == 's') {
				v = ucv_string_new_length(res, code->size);
			}
			else if (e->format == 'p') {
				ssize_t n = *(unsigned char *)res;

				if (n >= code->size)
					n = code->size - 1;

				v = ucv_string_new_length(res + 1, n);
			}
			else {
				v = e->unpack(vm, res, e);
			}

			if (v == NULL)
				goto fail;

			ucv_array_push(result, v);

			res += code->size;
		}
	}

	return result;

fail:
	ucv_put(result);

	return NULL;
}


static uc_value_t *
uc_pack(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *fmtval = uc_fn_arg(0);
	uc_value_t *res = NULL;
	formatstate_t *state;

	state = parse_format(vm, fmtval);

	if (!state)
		return NULL;

	res = uc_pack_common(vm, nargs, state, 1);

	free(state);

	return res;
}

static uc_value_t *
uc_unpack(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *fmtval = uc_fn_arg(0);
	uc_value_t *res = NULL;
	formatstate_t *state;

	state = parse_format(vm, fmtval);

	if (!state)
		return NULL;

	res = uc_unpack_common(vm, nargs, state, 1);

	free(state);

	return res;
}


static uc_value_t *
uc_struct_new(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *fmtval = uc_fn_arg(0);
	formatstate_t *state;

	state = parse_format(vm, fmtval);

	if (!state)
		return NULL;

	return uc_resource_new(struct_type, state);
}

static void
uc_struct_gc(void *ud)
{
	formatstate_t *state = ud;

	free(state);
}

static uc_value_t *
uc_struct_pack(uc_vm_t *vm, size_t nargs)
{
	formatstate_t **state = uc_fn_this("struct");

	if (!state || !*state)
		return NULL;

	return uc_pack_common(vm, nargs, *state, 0);
}

static uc_value_t *
uc_struct_unpack(uc_vm_t *vm, size_t nargs)
{
	formatstate_t **state = uc_fn_this("struct");

	if (!state || !*state)
		return NULL;

	return uc_unpack_common(vm, nargs, *state, 0);
}


static const uc_function_list_t struct_inst_fns[] = {
	{ "pack",	uc_struct_pack },
	{ "unpack",	uc_struct_unpack }
};

static const uc_function_list_t struct_fns[] = {
	{ "pack",	uc_pack },
	{ "unpack",	uc_unpack },
	{ "new",	uc_struct_new }
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	optimize_functions();

	uc_function_list_register(scope, struct_fns);

	struct_type = uc_type_declare(vm, "struct", struct_inst_fns, uc_struct_gc);
}
