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

/**
 * # Mathematical Functions
 *
 * The `math` module bundles various mathematical and trigonometrical functions.
 *
 * Functions can be individually imported and directly accessed using the
 * {@link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/import#named_import named import}
 * syntax:
 *
 *   ```
 *   import { pow, rand } from 'math';
 *
 *   let x = pow(2, 5);
 *   let y = rand();
 *   ```
 *
 * Alternatively, the module namespace can be imported
 * using a wildcard import statement:
 *
 *   ```
 *   import * as math from 'math';
 *
 *   let x = math.pow(2, 5);
 *   let y = math.rand();
 *   ```
 *
 * Additionally, the math module namespace may also be imported by invoking the
 * `ucode` interpreter with the `-lmath` switch.
 *
 * @module math
 */

#include <math.h>
#include <errno.h>
#include <sys/time.h>

#include "ucode/module.h"


/**
 * Returns the absolute value of the given numeric value.
 *
 * @function module:math#abs
 *
 * @param {*} number
 * The number to return the absolute value for.
 *
 * @returns {number}
 * Returns the absolute value or `NaN` if the given argument could
 * not be converted to a number.
 */
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

/**
 * Calculates the principal value of the arc tangent of `y`/`x`,
 * using the signs of the two arguments to determine the quadrant
 * of the result.
 *
 * On success, this function returns the principal value of the arc
 * tangent of `y`/`x` in radians; the return value is in the range [-pi, pi].
 *
 *  - If `y` is +0 (-0) and `x` is less than 0, +pi (-pi) is returned.
 *  - If `y` is +0 (-0) and `x` is greater than 0, +0 (-0) is returned.
 *  - If `y` is less than 0 and `x` is +0 or -0, -pi/2 is returned.
 *  - If `y` is greater than 0 and `x` is +0 or -0, pi/2 is returned.
 *  - If either `x` or `y` is NaN, a NaN is returned.
 *  - If `y` is +0 (-0) and `x` is -0, +pi (-pi) is returned.
 *  - If `y` is +0 (-0) and `x` is +0, +0 (-0) is returned.
 *  - If `y` is a finite value greater (less) than 0, and `x` is negative
 *    infinity, +pi (-pi) is returned.
 *  - If `y` is a finite value greater (less) than 0, and `x` is positive
 *    infinity, +0 (-0) is returned.
 *  - If `y` is positive infinity (negative infinity), and `x` is finite,
 *    pi/2 (-pi/2) is returned.
 *  - If `y` is positive infinity (negative infinity) and `x` is negative
 *    infinity, +3*pi/4 (-3*pi/4) is returned.
 *  - If `y` is positive infinity (negative infinity) and `x` is positive
 *    infinity, +pi/4 (-pi/4) is returned.
 *
 * When either `x` or `y` can't be converted to a numeric value, `NaN` is
 * returned.
 *
 * @function module:math#atan2
 *
 * @param {*} y
 * The `y` value.
 *
 * @param {*} x
 * The `x` value.
 *
 * @returns {number}
 */
static uc_value_t *
uc_atan2(uc_vm_t *vm, size_t nargs)
{
	double d1 = ucv_to_double(uc_fn_arg(0));
	double d2 = ucv_to_double(uc_fn_arg(1));

	if (isnan(d1) || isnan(d2))
		return ucv_double_new(NAN);

	return ucv_double_new(atan2(d1, d2));
}

/**
 * Calculates the cosine of `x`, where `x` is given in radians.
 *
 * Returns the resulting consine value.
 *
 * Returns `NaN` if the `x` value can't be converted to a number.
 *
 * @function module:math#cos
 *
 * @param {number} x
 * Radians value to calculate cosine for.
 *
 * @returns {number}
 */
static uc_value_t *
uc_cos(uc_vm_t *vm, size_t nargs)
{
	double d = ucv_to_double(uc_fn_arg(0));

	if (isnan(d))
		return ucv_double_new(NAN);

	return ucv_double_new(cos(d));
}

/**
 * Calculates the value of `e` (the base of natural logarithms)
 * raised to the power of `x`.
 *
 * On success, returns the exponential value of `x`.
 *
 *  - If `x` is positive infinity, positive infinity is returned.
 *  - If `x` is negative infinity, `+0` is returned.
 *  - If the result underflows, a range error occurs, and zero is returned.
 *  - If the result overflows, a range error occurs, and `Infinity` is returned.
 *
 * Returns `NaN` if the `x` value can't be converted to a number.
 *
 * @function module:math#exp
 *
 * @param {number} x
 * Power to raise `e` to.
 *
 * @returns {number}
 */
static uc_value_t *
uc_exp(uc_vm_t *vm, size_t nargs)
{
	double d = ucv_to_double(uc_fn_arg(0));

	if (isnan(d))
		return ucv_double_new(NAN);

	return ucv_double_new(exp(d));
}

/**
 * Calculates the natural logarithm of `x`.
 *
 * On success, returns the natural logarithm of `x`.
 *
 *  - If `x` is `1`, the result is `+0`.
 *  - If `x` is positive nfinity, positive infinity is returned.
 *  - If `x` is zero, then a pole error occurs, and the function
 *    returns negative infinity.
 *  - If `x` is negative (including negative infinity), then a domain
 *    error occurs, and `NaN` is returned.
 *
 * Returns `NaN` if the `x` value can't be converted to a number.
 *
 * @function module:math#log
 *
 * @param {number} x
 * Value to calulate natural logarithm of.
 *
 * @returns {number}
 */
static uc_value_t *
uc_log(uc_vm_t *vm, size_t nargs)
{
	double d = ucv_to_double(uc_fn_arg(0));

	if (isnan(d))
		return ucv_double_new(NAN);

	return ucv_double_new(log(d));
}

/**
 * Calculates the sine of `x`, where `x` is given in radians.
 *
 * Returns the resulting sine value.
 *
 *  - When `x` is positive or negative infinity, a domain error occurs
 *    and `NaN` is returned.
 *
 * Returns `NaN` if the `x` value can't be converted to a number.
 *
 * @function module:math#sin
 *
 * @param {number} x
 * Radians value to calculate sine for.
 *
 * @returns {number}
 */
static uc_value_t *
uc_sin(uc_vm_t *vm, size_t nargs)
{
	double d = ucv_to_double(uc_fn_arg(0));

	if (isnan(d))
		return ucv_double_new(NAN);

	return ucv_double_new(sin(d));
}

/**
 * Calculates the nonnegative square root of `x`.
 *
 * Returns the resulting square root value.
 *
 *  - If `x` is `+0` (`-0`) then `+0` (`-0`) is returned.
 *  - If `x` is positive infinity, positive infinity is returned.
 *  - If `x` is less than `-0`, a domain error occurs, and `NaN` is returned.
 *
 * Returns `NaN` if the `x` value can't be converted to a number.
 *
 * @function module:math#sqrt
 *
 * @param {number} x
 * Value to calculate square root for.
 *
 * @returns {number}
 */
static uc_value_t *
uc_sqrt(uc_vm_t *vm, size_t nargs)
{
	double d = ucv_to_double(uc_fn_arg(0));

	if (isnan(d))
		return ucv_double_new(NAN);

	return ucv_double_new(sqrt(d));
}

/**
 * Calculates the value of `x` raised to the power of `y`.
 *
 * On success, returns the value of `x` raised to the power of `y`.
 *
 *  - If the result overflows, a range error occurs, and the function
 *    returns `Infinity`.
 *  - If result underflows, and is not representable, a range error
 *    occurs, and `0.0` with the appropriate sign is returned.
 *  - If `x` is `+0` or `-0`, and `y` is an odd integer less than `0`,
 *    a pole error occurs `Infinity` is returned, with the same sign
 *    as `x`.
 *  - If `x` is `+0` or `-0`, and `y` is less than `0` and not an odd
 *    integer, a pole error occurs and `Infinity` is returned.
 *  - If `x` is `+0` (`-0`), and `y` is an odd integer greater than `0`,
 *    the result is `+0` (`-0`).
 *  - If `x` is `0`, and `y` greater than `0` and not an odd integer,
 *    the result is `+0`.
 *  - If `x` is `-1`, and `y` is positive infinity or negative infinity,
 *    the result is `1.0`.
 *  - If `x` is `+1`, the result is `1.0` (even if `y` is `NaN`).
 *  - If `y` is `0`, the result is `1.0` (even if `x` is `NaN`).
 *  - If `x` is a finite value less than `0`, and `y` is a finite
 *    noninteger, a domain error occurs, and `NaN` is returned.
 *  - If the absolute value of `x` is less than `1`, and `y` is negative
 *    infinity, the result is positive infinity.
 *  - If the absolute value of `x` is greater than `1`, and `y` is
 *    negative infinity, the result is `+0`.
 *  - If the absolute value of `x` is less than `1`, and `y` is positive
 *    infinity, the result is `+0`.
 *  - If the absolute value of `x` is greater than `1`, and `y` is positive
 *    infinity, the result is positive infinity.
 *  - If `x` is negative infinity, and `y` is an odd integer less than `0`,
 *    the result is `-0`.
 *  - If `x` is negative infinity, and `y` less than `0` and not an odd
 *    integer, the result is `+0`.
 *  - If `x` is negative infinity, and `y` is an odd integer greater than
 *    `0`, the result is negative infinity.
 *  - If `x` is negative infinity, and `y` greater than `0` and not an odd
 *    integer, the result is positive infinity.
 *  - If `x` is positive infinity, and `y` less than `0`, the result is `+0`.
 *  - If `x` is positive infinity, and `y` greater than `0`, the result is
 *    positive infinity.
 *
 * Returns `NaN` if either the `x` or `y` value can't be converted to a number.
 *
 * @function module:math#pow
 *
 * @param {number} x
 * The base value.
 *
 * @param {number} y
 * The power value.
 *
 * @returns {number}
 */
static uc_value_t *
uc_pow(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));
	double y = ucv_to_double(uc_fn_arg(1));

	if (isnan(x) || isnan(y))
		return ucv_double_new(NAN);

	return ucv_double_new(pow(x, y));
}

/**
 * Depending on the arguments, it produces a pseudo-random positive integer, 
 * or a pseudo-random number in a supplied range.
 *
 * Without arguments it returns the calculated pseuo-random value. The value 
 * is within the range `0` to `RAND_MAX` inclusive where `RAND_MAX` is a platform 
 * specific value guaranteed to be at least `32767`.
 * 
 * With 2 arguments `a, b` it returns a number in the range `a` to `b` inclusive.
 * With a single argument `a` it returns a number in the range `0` to `a` inclusive.
 * 
 * The {@link module:math~srand `srand()`} function sets its argument as the
 * seed for a new sequence of pseudo-random integers to be returned by `rand()`.
 * These sequences are repeatable by calling {@link module:math~srand `srand()`}
 * with the same seed value.
 *
 * If no seed value is explicitly set by calling
 * {@link module:math~srand `srand()`} prior to the first call to `rand()`,
 * the math module will automatically seed the PRNG once, using the current
 * time of day in milliseconds as seed value.
 *
 * @function module:math#rand
 *
 * @param {number} [a]
 * End of the desired range.
 * 
 * @param {number} [b]
 * The other end of the desired range.
 * 
 * @returns {number}
 */
static uc_value_t *
uc_rand(uc_vm_t *vm, size_t nargs)
{
	struct timeval tv;

	if (!ucv_boolean_get(uc_vm_registry_get(vm, "math.srand_called"))) {
		gettimeofday(&tv, NULL);
		srand((tv.tv_sec * 1000) + (tv.tv_usec / 1000));

		uc_vm_registry_set(vm, "math.srand_called", ucv_boolean_new(true));
	}

	if (nargs == 0)
		return ucv_int64_new(rand());

	double a = ucv_to_double(uc_fn_arg(0)), b = 0;

	if (nargs > 1)
		b = ucv_to_double(uc_fn_arg(1));

	return ucv_double_new(a + ((b - a) * rand()) / RAND_MAX);
}

/**
 * Seeds the pseudo-random number generator.
 *
 * This functions seeds the PRNG with the given value and thus affects the
 * pseudo-random integer sequence produced by subsequent calls to
 * {@link module:math~rand `rand()`}.
 *
 * Setting the same seed value will result in the same pseudo-random numbers
 * produced by {@link module:math~rand `rand()`}.
 *
 * @function module:math#srand
 *
 * @param {number} seed
 * The seed value.
 */
static uc_value_t *
uc_srand(uc_vm_t *vm, size_t nargs)
{
	int64_t n = ucv_to_integer(uc_fn_arg(0));

	srand((unsigned int)n);
	uc_vm_registry_set(vm, "math.srand_called", ucv_boolean_new(true));

	return NULL;
}

/**
 * Tests whether `x` is a `NaN` double.
 *
 * This functions checks whether the given argument is of type `double` with
 * a `NaN` (not a number) value.
 *
 * Returns `true` if the value is `NaN`, otherwise false.
 *
 * Note that a value can also be checked for `NaN` with the expression
 * `x !== x` which only evaluates to `true` if `x` is `NaN`.
 *
 * @function module:math#isnan
 *
 * @param {number} x
 * The value to test.
 *
 * @returns {boolean}
 */
static uc_value_t *
uc_isnan(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *v = uc_fn_arg(0);

	return ucv_boolean_new(ucv_type(v) == UC_DOUBLE && isnan(ucv_double_get(v)));
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
	{ "isnan",	uc_isnan },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, math_fns);

	uc_vm_registry_set(vm, "math.srand_called", ucv_boolean_new(false));
}
