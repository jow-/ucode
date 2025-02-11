/*
 * Copyright (C) 2024 Jo-Philipp Wich <jo@mein.io>
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

#include <errno.h>
#include <limits.h>
#include <math.h>

#include "ucode/arith.h"


static int64_t
int64(uc_value_t *nv, uint64_t *u64)
{
	int64_t n;

	n = ucv_int64_get(nv);
	*u64 = 0;

	if (errno == ERANGE) {
		n = INT64_MAX;
		*u64 = ucv_uint64_get(nv);
	}

	return n;
}

static uint64_t
abs64(int64_t n)
{
	if (n == INT64_MIN)
		return 0x8000000000000000ULL;

	if (n < 0)
		return -n;

	return n;
}

static uint64_t
upow64(uint64_t base, uint64_t exponent)
{
	uint64_t result = 1;

	while (exponent) {
		if (exponent & 1)
			result *= base;

		exponent >>= 1;
		base *= base;
	}

	return result;
}


static uc_value_t *
ucv_arith_logic_result(uc_tokentype_t operation, uc_value_t *v1, uc_value_t *v2)
{
	switch (operation) {
	case TK_AND:     return ucv_get(ucv_is_truish(v1) ? v2 : v1);
	case TK_OR:      return ucv_get(ucv_is_truish(v1) ? v1 : v2);
	case TK_NULLISH: return ucv_get(v1 ? v1 : v2);
	case TK_IN:      return ucv_boolean_new(ucv_contains(v2, v1));
	default:         return NULL;
	}
}

static uc_value_t *
ucv_arith_bitwise_result(uc_tokentype_t operation, uc_value_t *v1, uc_value_t *v2)
{
	uc_value_t *nv1, *nv2, *rv = NULL;
	uint64_t u1, u2;
	int64_t n1, n2;

	nv1 = ucv_to_number(v1);
	nv2 = ucv_to_number(v2);

	n1 = int64(nv1, &u1);
	n2 = int64(nv2, &u2);

	if (n1 < 0 || n2 < 0) {
		switch (operation) {
		case TK_LSHIFT:
			rv = ucv_int64_new(n1 << n2);
			break;

		case TK_RSHIFT:
			rv = ucv_int64_new(n1 >> n2);
			break;

		case TK_BAND:
			rv = ucv_int64_new(n1 & n2);
			break;

		case TK_BXOR:
			rv = ucv_int64_new(n1 ^ n2);
			break;

		case TK_BOR:
			rv = ucv_int64_new(n1 | n2);
			break;

		default:
			break;
		}
	}
	else {
		if (!u1) u1 = (uint64_t)n1;
		if (!u2) u2 = (uint64_t)n2;

		switch (operation) {
		case TK_LSHIFT:
			rv = ucv_uint64_new(u1 << (u2 % (sizeof(uint64_t) * CHAR_BIT)));
			break;

		case TK_RSHIFT:
			rv = ucv_uint64_new(u1 >> (u2 % (sizeof(uint64_t) * CHAR_BIT)));
			break;

		case TK_BAND:
			rv = ucv_uint64_new(u1 & u2);
			break;

		case TK_BXOR:
			rv = ucv_uint64_new(u1 ^ u2);
			break;

		case TK_BOR:
			rv = ucv_uint64_new(u1 | u2);
			break;

		default:
			break;
		}
	}

	ucv_put(nv1);
	ucv_put(nv2);

	return rv;
}

static uc_value_t *
ucv_arith_string_concat(uc_vm_t *vm, uc_value_t *v1, uc_value_t *v2)
{
	char buf[sizeof(void *)], *s1, *s2;
	uc_stringbuf_t *sbuf;
	size_t l1, l2;

	/* optimize cases for string+string concat... */
	if (ucv_type(v1) == UC_STRING && ucv_type(v2) == UC_STRING) {
		s1 = ucv_string_get(v1);
		s2 = ucv_string_get(v2);
		l1 = ucv_string_length(v1);
		l2 = ucv_string_length(v2);

		/* ... result fits into a tagged pointer */
		if (l1 + l2 + 1 < sizeof(buf)) {
			memcpy(&buf[0], s1, l1);
			memcpy(&buf[l1], s2, l2);

			return ucv_string_new_length(buf, l1 + l2);
		}
	}

	sbuf = ucv_stringbuf_new();

	ucv_to_stringbuf(vm, sbuf, v1, false);
	ucv_to_stringbuf(vm, sbuf, v2, false);

	return ucv_stringbuf_finish(sbuf);
}

uc_value_t *
ucv_arith_binary(uc_vm_t *vm, uc_tokentype_t operation, uc_value_t *v1, uc_value_t *v2)
{
	uc_value_t *nv1, *nv2, *rv = NULL;
	uint64_t u1, u2;
	int64_t n1, n2;
	double d1, d2;

	if (operation == TK_AND || operation == TK_OR ||
	    operation == TK_NULLISH || operation == TK_IN)
		return ucv_arith_logic_result(operation, v1, v2);

	if (operation == TK_LSHIFT || operation == TK_RSHIFT ||
	    operation == TK_BAND || operation == TK_BXOR || operation == TK_BOR)
		return ucv_arith_bitwise_result(operation, v1, v2);

	if (operation == TK_ADD &&
	    (ucv_type(v1) == UC_STRING || ucv_type(v2) == UC_STRING))
		return ucv_arith_string_concat(vm, v1, v2);

	nv1 = ucv_to_number(v1);
	nv2 = ucv_to_number(v2);

	/* any operation involving NaN results in NaN */
	if (!nv1 || !nv2) {
		ucv_put(nv1);
		ucv_put(nv2);

		return ucv_double_new(NAN);
	}
	if (ucv_type(nv1) == UC_DOUBLE || ucv_type(nv2) == UC_DOUBLE) {
		d1 = ucv_double_get(nv1);
		d2 = ucv_double_get(nv2);

		switch (operation) {
		case TK_ADD:
		case TK_INC:
			rv = ucv_double_new(d1 + d2);
			break;

		case TK_SUB:
		case TK_DEC:
			rv = ucv_double_new(d1 - d2);
			break;

		case TK_MUL:
			rv = ucv_double_new(d1 * d2);
			break;

		case TK_DIV:
			if (d2 == 0.0)
				rv = ucv_double_new(INFINITY);
			else if (isnan(d2))
				rv = ucv_double_new(NAN);
			else if (!isfinite(d2))
				rv = ucv_double_new(isfinite(d1) ? 0.0 : NAN);
			else
				rv = ucv_double_new(d1 / d2);

			break;

		case TK_MOD:
			rv = ucv_double_new(fmod(d1, d2));
			break;

		case TK_EXP:
			rv = ucv_double_new(pow(d1, d2));
			break;

		default:
			if (vm)
				uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
				                      "undefined arithmetic operation %d",
				                      operation);

			break;
		}
	}
	else {
		n1 = int64(nv1, &u1);
		n2 = int64(nv2, &u2);

		switch (operation) {
		case TK_ADD:
		case TK_INC:
			if (n1 < 0 || n2 < 0) {
				if (u1)
					rv = ucv_uint64_new(u1 - abs64(n2));
				else if (u2)
					rv = ucv_uint64_new(u2 - abs64(n1));
				else
					rv = ucv_int64_new(n1 + n2);
			}
			else {
				if (!u1) u1 = (uint64_t)n1;
				if (!u2) u2 = (uint64_t)n2;

				rv = ucv_uint64_new(u1 + u2);
			}

			break;

		case TK_SUB:
		case TK_DEC:
			if (n1 < 0 && n2 < 0) {
				if (n1 > n2)
					rv = ucv_uint64_new(abs64(n2) - abs64(n1));
				else
					rv = ucv_int64_new(n1 - n2);
			}
			else if (n1 >= 0 && n2 >= 0) {
				if (!u1) u1 = (uint64_t)n1;
				if (!u2) u2 = (uint64_t)n2;

				if (u2 > u1)
					rv = ucv_int64_new(-(u2 - u1));
				else
					rv = ucv_uint64_new(u1 - u2);
			}
			else if (n1 >= 0) {
				if (!u1) u1 = (uint64_t)n1;

				rv = ucv_uint64_new(u1 + abs64(n2));
			}
			else {
				rv = ucv_int64_new(n1 - n2);
			}

			break;

		case TK_MUL:
			if (n1 < 0 && n2 < 0) {
				rv = ucv_uint64_new(abs64(n1) * abs64(n2));
			}
			else if (n1 >= 0 && n2 >= 0) {
				if (!u1) u1 = (uint64_t)n1;
				if (!u2) u2 = (uint64_t)n2;

				rv = ucv_uint64_new(u1 * u2);
			}
			else {
				rv = ucv_int64_new(n1 * n2);
			}

			break;

		case TK_DIV:
			if (n2 == 0) {
				rv = ucv_double_new(INFINITY);
			}
			else if (n1 < 0 || n2 < 0) {
				rv = ucv_int64_new(n1 / n2);
			}
			else {
				if (!u1) u1 = (uint64_t)n1;
				if (!u2) u2 = (uint64_t)n2;

				rv = ucv_uint64_new(u1 / u2);
			}

			break;

		case TK_MOD:
			if (n1 < 0 || n2 < 0) {
				rv = ucv_int64_new(n1 % n2);
			}
			else {
				if (!u1) u1 = (uint64_t)n1;
				if (!u2) u2 = (uint64_t)n2;

				rv = ucv_uint64_new(u1 % u2);
			}

			break;

		case TK_EXP:
			if (n1 < 0 || n2 < 0) {
				if (n1 < 0 && n2 < 0)
					rv = ucv_double_new(-(1.0 / (double)upow64(abs64(n1), abs64(n2))));
				else if (n2 < 0)
					rv = ucv_double_new(1.0 / (double)upow64(abs64(n1), abs64(n2)));
				else
					rv = ucv_int64_new(-upow64(abs64(n1), abs64(n2)));
			}
			else {
				if (!u1) u1 = (uint64_t)n1;
				if (!u2) u2 = (uint64_t)n2;

				rv = ucv_uint64_new(upow64(u1, u2));
			}

			break;

		default:
			if (vm)
				uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
				                      "undefined arithmetic operation %d",
				                      operation);

			break;
		}
	}

	ucv_put(nv1);
	ucv_put(nv2);

	return rv;
}

uc_value_t *
ucv_arith_unary(uc_vm_t *vm, uc_tokentype_t operation, uc_value_t *v)
{
	uc_value_t *nv = NULL, *rv = NULL;
	bool is_sub = false;
	uint64_t u;
	int64_t n;
	double d;

	switch (operation) {
	case TK_SUB:
	case TK_DEC:
		is_sub = true;
		/* fall through */

	case TK_ADD:
	case TK_INC:
		if (ucv_type(v) == UC_STRING) {
			nv = uc_number_parse(ucv_string_get(v), NULL);

			if (!nv)
				nv = ucv_get(v);
		}
		else {
			nv = ucv_get(v);
		}

		switch (ucv_type(nv)) {
		case UC_INTEGER:
			n = ucv_int64_get(nv);

			/* numeric value is in range 9223372036854775808..18446744073709551615 */
			if (errno == ERANGE) {
				if (is_sub)
					/* make negation of large numeric value result in smallest negative value */
					rv = ucv_int64_new(INT64_MIN);
				else
					/* for positive number coercion return value as-is */
					rv = ucv_get(nv);
			}

			/* numeric value is in range -9223372036854775808..9223372036854775807 */
			else {
				if (is_sub) {
					if (n == INT64_MIN)
						/* make negation of minimum value result in maximum signed positive value */
						rv = ucv_int64_new(INT64_MAX);
					else
						/* for all other values flip the sign */
						rv = ucv_int64_new(-n);
				}
				else {
					/* for positive number coercion return value as-is */
					rv = ucv_get(nv);
				}
			}

			break;

		case UC_DOUBLE:
			d = ucv_double_get(nv);
			rv = ucv_double_new(is_sub ? -d : d);
			break;

		case UC_BOOLEAN:
			n = (int64_t)ucv_boolean_get(v);
			rv = ucv_int64_new(is_sub ? -n : n);
			break;

		case UC_NULL:
			rv = ucv_int64_new(0);
			break;

		default:
			rv = ucv_double_new(NAN);
		}

		break;

	case TK_COMPL:
	 	nv = ucv_to_number(v);
		n = int64(nv, &u);

		if (n < 0) {
			rv = ucv_int64_new(~n);
		}
		else {
			if (!u) u = (uint64_t)n;

			rv = ucv_uint64_new(~u);
		}

		break;

	default:
		if (vm)
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			                      "undefined unary operation %d", operation);

		break;
	}

	ucv_put(nv);

	return rv;
}
