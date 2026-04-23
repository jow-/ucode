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
 * It should be noted that when the ucode interpreter is run as `-p "..."`,
 * values involving Infinity are returned as the max double precision value
 * +/-1e309 (JSON), whereas when run as `-e "print(...)"` Infinity is
 * represented by the string `Infinity`. The boolean check `isinf()` is
 * available to determine Infinity values.
 *
 * @module math
 */

#include <math.h>
#include <errno.h>
#include <sys/time.h>

#include "ucode/module.h"

#ifndef M_PI
#define M_PI   3.14159265358979323846264338327950288
#endif
#define degToRad(angleInDegrees) ((angleInDegrees) * M_PI / 180.0)
#define radToDeg(angleInRadians) ((angleInRadians) * 180.0 / M_PI)


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
 * Calculates the arc cosine of `x`.
 *
 * On success, this function returns the principal value of the arc
 * cosine of `x` in radians; the return value is in the range [pi, 0].
 *
 *  - If `x` is -1, pi is returned.
 *  - If `x` is  0, pi/2 is returned.
 *  - If `x` is +1, 0 is returned.
 *
 * When `x` can't be converted to a numeric value, `NaN` is
 * returned.
 *
 * @function module:math#acos
 *
 * @param {double} x
 * The `x` value.
 *
 * @returns {double}
 * @example
 * acos(-1); // 3.1415926535898 i.e. pi
 * acos(0);  // 1.5707963267949 i.e. pi/2
 * acos(1);  // 0.0 i.e. 0 pi
 */
static uc_value_t *
uc_arccos(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_double_new(acos(x));
}

/**
 * Calculates the arc sine of `x`.
 *
 * On success, this function returns the principal value of the arc
 * sine of `x` in radians; the return value is in the range [-pi/2, pi/2].
 *
 *  - If `x` is +0 (-0), 0 is returned.
 *  - If `x` is +1 (-1), pi/2 (-pi/2) is returned.
 *
 * When `x` can't be converted to a numeric value, `NaN` is
 * returned.
 *
 * @function module:math#asin
 *
 * @param {double} x
 * The `x` value.
 *
 * @returns {double}
 * @example
 * asin(-1); // -1.5707963267949 i.e. -pi/2
 * asin(0);  // 0.0 i.e. 0 pi
 * asin(1);  // 1.5707963267949 i.e. pi/2
 */
static uc_value_t *
uc_arcsin(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_double_new(asin(x));
}

/**
 * Calculates the arc tangent of `x`.
 *
 * On success, this function returns the principal value of the arc
 * tangent of `x` in radians; the return value is in the range [-pi/2, pi/2].
 *
 *  - If `x` is +0 (-0), 0 is returned.
 *  - As `x` tends toward +Infinity (-Infinity), the return value asymptotically
 * converges toward pi/2 (-pi/2).
 *
 * When `x` can't be converted to a numeric value, `NaN` is
 * returned.
 *
 * @function module:math#atan
 *
 * @param {double} x
 * The `x` value.
 *
 * @returns {double}
 * @example
 * atan(-100000); // -1.5707863267949 i.e. ~ -pi/2
 * atan(0);       // 0.0 i.e. 0 pi
 * atan(100000);  // 1.5707863267949 i.e. ~ pi/2
 */
static uc_value_t *
uc_arctan(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_double_new(atan(x));
}

/**
 * Calculates the hyperbolic cosine of `x`.
 *
 * On success, this function returns the principal value of the hyperbolic
 * cosine of `x`; the return value is in the range [Infinity, 1].
 * 
 * The relationship is: cosh = `((e^x) + (e^-x)) / 2`.
 *
 *  - As `x` decreases below -1, the return value exponentiates toward Infinity.
 *  - If `x` is  0, 1 is returned.
 *  - As `x` increases above +1, the return value exponentiates toward Infinity.
 *
 * When `x` can't be converted to a numeric value, `NaN` is
 * returned.
 *
 * @function module:math#cosh
 *
 * @param {double} x
 * The `x` value.
 *
 * @returns {double}
 * @example
 * cosh(-10); // 11013.232920103
 * cosh(-1);  // 1.5430806348152
 * cosh(0);   // 1.0
 * cosh(1);   // 1.5430806348152
 * cosh(10);  // 11013.232920103
 */
static uc_value_t *
uc_cosh(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_double_new(cosh(x));
}

/**
 * Calculates the hyperbolic sine of `x`.
 *
 * On success, this function returns the principal value of the hyperbolic
 * sine of `x`; the return value is in the range [-Infinity, Infinity].
 *  
 * The relationship is: sinh = `((e^x) - (e^-x)) / 2`.
 *
 *  - As `x` decreases below -1, the return value exponentiates toward -Infinity.
 *  - If `x` is  0, 0 is returned.
 *  - As `x` increases above +1, the return value exponentiates toward Infinity.
 *
 * When `x` can't be converted to a numeric value, `NaN` is
 * returned.
 *
 * @function module:math#sinh
 *
 * @param {double} x
 * The `x` value.
 *
 * @returns {double}
 * @example
 * sinh(-10); // -11013.232920103
 * sinh(-1);  // -1.1752011936438
 * sinh(0);   // 0.0
 * sinh(1);   // 1.1752011936438
 * sinh(10);  // 11013.232920103
 */
static uc_value_t *
uc_sinh(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_double_new(sinh(x));
}

/**
 * Calculates the hyperbolic tangent of `x`.
 *
 * On success, this function returns the principal value of the hyperbolic
 * tangent of `x`; the return value is in the range [-1, 1].
 *
 * The relationship is: tanh = `((e^x) - (e^-x)) / ((e^x) + (e^-x))`, or
 * tanh = `sinh(x) / cosh(x)`.
 *
 *  - As `x` decreases below -1, the return value asymptotically expands
 * toward -1.
 *  - If `x` is  0, 0 is returned.
 *  - As `x` increases above +1, the return value asymptotically expands
 * toward 1.
 *
 * When `x` can't be converted to a numeric value, `NaN` is
 * returned.
 *
 * @function module:math#tanh
 *
 * @param {double} x
 * The `x` value.
 *
 * @returns {double}
 * @example
 * atan(-100); // -1.0
 * atan(-10);  // -0.99999999587769
 * atan(0);    // 0.0
 * atan(10);   // 0.99999999587769
 * atan(100);  // 1.0
 */
static uc_value_t *
uc_tanh(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_double_new(tanh(x));
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
 * Calculates the tangent of `x`, the floating-point value representing the
 * angle in radians.
 *
 * On success, this function returns the tangent of `x`.
 * 
 * The relationship is `tan(x) = sin(x) / cos (x)`. A graph of the tangent has
 * periodic patterns directly related to ratios of pi, where radian values of
 * whole multiples of (1, 2, 3, ...) pi are 0, and radian values of half
 * multiples of pi (1/2, 3/2, 5/2, ...) are +/-Infinity.
 *
 *
 * When `x` can't be converted to a numeric value, `NaN` is
 * returned.
 *
 * @function module:math#tan
 *
 * @param {double} x
 * The `x` value.
 *
 * @returns {double}
 */
static uc_value_t *
uc_tan(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_double_new(tan(x));
}

/**
 * Calculates the cosine of `x`, where `x` is given in radians.
 *
 * Returns the resulting cosine value.
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
 *  - If `x` is positive infinity, positive infinity is returned.
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
 * Value to calculate natural logarithm of.
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
 * Calculate base-10 log of x.
 *
 * @function module:math#log10
 *
 * @param {double} x number
 *
 * @returns {double}
 * The common (base-10) logarithm of x, or
 * `NaN` if the given argument could not be converted to a number.
 *
 * @example
 * log10(100);   // 2.0
 * log10(10);    // 1.0
 * log10(5);     // 0.69897000433602
 * log10(1);     // 0.0
 * log10(0);     // -1e309
 */
static uc_value_t *
uc_log10(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_double_new(log10(x));
}

/**
 * Calculate base-2 log of x.
 *
 * @function module:math#log2
 *
 * @param {double} x number
 *
 * @returns {double}
 * The common (base-2) logarithm of x, or
 * `NaN` if the given argument could not be converted to a number.
 *
 * @example
 * log2(1024);  // 10.0
 * log2(512);   // 9.0
 * log2(16);    // 4.0
 * log2(4);     // 2.0
 * log2(2);     // 1.0
 * log2(1);     // 0.0
 * log2(0);     // -1e309
 */
static uc_value_t *
uc_log2(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_double_new(log2(x));
}

/**
 * Computes the natural (base e) logarithm of 1 + x. This function is more
 * precise than the expression {@link module:math#log `log`}(1 + x) if x is
 * close to zero.
 *
 * @function module:math#log1p
 *
 * @param {double} x number
 *
 * @returns {double}
 * The natural (base e) logarithm of 1 + x, or
 * `NaN` if the given argument could not be converted to a number.
 *
 * @example
 * log1p(10);    // 2.3978952727984
 * log1p(1);     // 0.69314718055995
 * log1p(0.1);   // 0.095310179804325
 * log1p(0.001); // 0.00099950033308353
 * log1p(0);     // 0.0
 */
static uc_value_t *
uc_log1p(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_double_new(log1p(x));
}

/**
 * Computes the e (Euler's number, 2.7182818) raised to the given power x,
 * minus 1.0. This function is more accurate than the expression 
 * {@link module:math#exp `exp(x)`}-1.0
 * if x is close to zero.
 *
 * @function module:math#expm1
 *
 * @param {double} x number
 *
 * @returns {double}
 * The e (Euler's number, 2.7182818) raised to the given power x, minus 1.0, or
 * `NaN` if the given argument could not be converted to a number.
 *
 * @example
 * expm1(10);       // 22025.465794807
 * expm1(1);        // 1.718281828459
 * expm1(0.1);      // 0.10517091807565
 * expm1(0.001);    // 0.0010005001667083
 * exp(0.001)-1;    // 0.0010005001667084
 * expm1(0.0001);   // 0.00010000500016667
 * exp(0.0001)-1;   // 0.00010000500016671
 * expm1(0.000001); // 1.0000005000002e-06
 * exp(0.000001)-1; // 1.0000004999622e-06
 * expm1(0);        // 0.0
 */
static uc_value_t *
uc_expm1(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_double_new(expm1(x));
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
 * Calculates the non-negative square root of `x`.
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
 * Calculates the cube root of `x`.
 *
 * Returns the resulting cube root value.
 *
 *  - If `x` is `+0` (`-0`) then `+0` (`-0`) is returned.
 *  - If `x` is (+/-) infinity, (+/-) infinity is returned.
 *
 * Returns `NaN` if the `x` value can't be converted to a number.
 *
 * @function module:math#cbrt
 *
 * @param {double} x
 * Value to calculate cube root for.
 *
 * @returns {double}
 * @example
 * cbrt(27);  // 3.0
 * cbrt(0);   // 0.0
 * cbrt(-27); // -3.0
 */
static uc_value_t *
uc_cbrt(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_double_new(cbrt(x));
}

/**
 * Computes the square root of the sum of the squares of `x` and `y`, i.e.
 * the hypotenuse without undue overflow or underflow at intermediate stages of
 * the computation.
 *
 * Returns the result of `sqrt(x^2 + y^2)`.
 *
 *  - If `x` and `y` are `+0` (`-0`) then `+0` (`-0`) is returned.
 *  - If `x` or `y` is `+0` (`-0`) then `+y` or `+x` is returned.
 *  - If `x` or `y` is (+/-) infinity, (+/-) infinity is returned.
 *
 * Returns `NaN` if the `x` or `y` value can't be converted to a number.
 *
 * @function module:math#hypot
 *
 * @param {double} x base
 * @param {double} y height
 *
 * @returns {double}
 * @example
 * hypot(3, 3);   // 4.2426406871193
 * hypot(2, 2);   // 2.8284271247462
 * hypot(1, 1);   // 1.4142135623731
 * hypot(0, 0);   // 0.0
 * hypot(-1, -1); // -1.4142135623731
 */
static uc_value_t *
uc_hypot(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));
	double y = ucv_to_double(uc_fn_arg(1));

	if (isnan(x) || isnan(y))
		return ucv_double_new(NAN);

	return ucv_double_new(hypot(x, y));
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
 *    non-integer, a domain error occurs, and `NaN` is returned.
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

/**
 * Tests whether `x` is double precision `Infinity`.
 *
 * This functions checks whether the given argument is of type `double` of
 * `Infinity` value. Double precision values >= 1.8e308 are considered `Infinity`.
 *
 * Returns `true` if the value is `Infinity`, otherwise false.
 *
 * @function module:math#isinf
 *
 * @param {number} x
 * The value to test.
 *
 * @returns {boolean}
 */
static uc_value_t *
uc_isinf(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *v = uc_fn_arg(0);

	return ucv_boolean_new(ucv_type(v) == UC_DOUBLE && isinf(ucv_double_get(v)));
}

/**
 * Returns the radian value of the given degree value.
 *
 * @function module:math#deg2rad
 *
 * @param {double} number
 * The number to return the radian value for.
 *
 * @returns {number}
 * Returns the absolute value or `NaN` if the given argument could
 * not be converted to a number.
 * @example
 * deg2rad(180);   // 3.1415926535898
 * deg2rad("180"); // 3.1415926535898
 */
static uc_value_t *
uc_deg2rad(uc_vm_t *vm, size_t nargs)
{
	double d = ucv_to_double(uc_fn_arg(0));

	return ucv_double_new(degToRad(d));
}

/**
 * Returns the degree value of the given radian value.
 *
 * @function module:math#rad2deg
 *
 * @param {double} number
 * The number to return the degree value for.
 *
 * @returns {number}
 * Returns the absolute value or `NaN` if the given argument could
 * not be converted to a number.
 * @example
 * rad2deg(3.1415926535898);   // 180.0
 * rad2deg("3.1415926535898"); // 180.0
 */
static uc_value_t *
uc_rad2deg(uc_vm_t *vm, size_t nargs)
{
	double d = ucv_to_double(uc_fn_arg(0));

	return ucv_double_new(radToDeg(d));
}

/**
 * Returns the lesser of two values x and y.
 *
 * @function module:math#fmin
 *
 * @param {double} x first parameter
 * @param {double} y second parameter
 *
 * @returns {double}
 * Returns the lesser of the two values x or y or `NaN` if a given argument
 * could not be converted to a number. Use `(-)Infinity` or `NAN` for
 * comparisons involving said values.
 * @example
 * fmin("180", "-180");   // -180.0
 * fmin(180, -180);       // -180.0
 * fmin(-Infinity, 0);    // -1e309 i.e. -infinity in double type representation.
 */
static uc_value_t *
uc_fmin(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));
	double y = ucv_to_double(uc_fn_arg(1));

	if (isnan(x) || isnan(y))
		return ucv_double_new(NAN);

	return ucv_double_new(fmin(x, y));
}

/**
 * Returns the greater of two values x and y.
 *
 * @function module:math#fmax
 *
 * @param {double} x first parameter
 * @param {double} y second parameter
 *
 * @returns {double}
 * Returns the greater of the two values x or y or `NaN` if a given argument
 * could not be converted to a number. Use `(-)Infinity` or `NAN` for
 * comparisons involving said values.
 * @example
 * fmax("180", "-180");   // 180.0
 * fmax(180, -180);       // 180.0
 * fmax(Infinity, 0);     // 1e309 i.e. infinity in double type representation.
 */
static uc_value_t *
uc_fmax(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));
	double y = ucv_to_double(uc_fn_arg(1));

	if (isnan(x) || isnan(y))
		return ucv_double_new(NAN);

	return ucv_double_new(fmax(x, y));
}

/**
 * Clamps `x` to within `upper` and `lower` bounds if `x` exceeds them.
 *
 * The operation is effectively: `min(upper, max(x, lower))`.
 *
 * @function module:math#clamp
 *
 * @param {double} x number to clamp
 * @param {double} upper upper bound
 * @param {double} lower lower bound
 *
 * @returns {double}
 * Returns `x` if within `upper` and `lower`, otherwise one of `lower` or `upper`
 * if `x` exceeds those bounds, or `NaN` if any given argument
 * could not be converted to a number.
 * @example
 * clamp(1000, 200, 180);   // 200.0
 * clamp(-1000, 200, 180);  // 180.0
 * clamp(190, 200, 180);    // 190.0
 */
static uc_value_t *
uc_clamp(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));
	double upper = ucv_to_double(uc_fn_arg(1));
	double lower = ucv_to_double(uc_fn_arg(2));

	if (isnan(x) || isnan(upper) || isnan(lower))
		return ucv_double_new(NAN);

	return ucv_double_new(fmin(upper, fmax(x, lower)));
}

/**
 * Returns -1 or 1 depending on the sign of the given number, or 0 if the given
 * number itself is zero.
 *
 * @function module:math#sign
 *
 * @param {double} x number
 *
 * @returns {integer}
 * Returns -1 or 1 for negative and positive inputs respectively, 0 if the given
 * number is zero, or `NaN` if the given argument could not be converted to a
 * number.
 * @example
 * sign(2);   // 1
 * sign(-8);  // -1
 * sign(0);   // 0
 * sign(-0);  // 0
 */
static uc_value_t *
uc_sign(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_int64_new((x > 0) - (x < 0));
}

/**
 * Returns -1 or 1 depending on the sign of the given number, or 0 if the given
 * number itself is zero. IEEE-754 behaviour.
 *
 * @function module:math#signbit
 *
 * @param {double} x number
 *
 * @returns {integer}
 * Returns -1 or 1 for negative and positive inputs respectively, 0 if the given
 * number is zero, -1 for -0.0, or `NaN` if the given argument could not be
 * converted to a number.
 * @example
 * signbit(2);    // 1
 * signbit(-8);   // -1
 * signbit(0);    // 0
 * signbit(-0.0); // -1
 * signbit(-0);   // 0
 */
static uc_value_t *
uc_signbit(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_int64_new(signbit(x) ? -1 : (x > 0));
}

/**
 * Returns -1 or 1 depending on the sign of the given number only (no zero).
 * (-)Zero effectively becomes 1.
 *
 * @function module:math#signnz
 *
 * @param {double} x number
 *
 * @returns {integer}
 * Returns -1 or +1 for negative and positive inputs respectively, and zero is
 * converted to +1, or `NaN` if the given argument could not be converted to a
 * number.
 * @example
 * signnz(2);   // 1
 * signnz(-8);  // -1
 * signnz(0);   // 1
 * signnz(-0);  // 1
 */
static uc_value_t *
uc_signnz(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_int64_new((x >= 0) ? 1 : -1);
}

/**
 * Returns a double whose magnitude is that of `x`, but whose sign is that of
 * `y`.
 *
 * @function module:math#copysign
 *
 * @param {double} x number
 * @param {double} y number
 *
 * @returns {double}
 * Returns `NaN` if a given argument could not be converted to a number.
 * @example
 * copysign(-3, -5);  // -3.0
 * copysign(8, -5);   // -8.0
 * copysign(-0, 3);   // 0.0
 */
static uc_value_t *
uc_copysign(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));
	double y = ucv_to_double(uc_fn_arg(1));

	if (isnan(x) || isnan(y))
		return ucv_double_new(NAN);

	return ucv_double_new(copysign(x, y));
}

/**
 * Floors `x` to the largest integer value not greater than `x`.
 *
 * @function module:math#floor
 *
 * @param {double} x number
 *
 * @returns {double}
 * Returns the largest integer value not greater than `x`, or `NaN` if the given
 * argument could not be converted to a number.
 * @example
 * floor(2.7);        // 2.0
 * floor(-2.7);       // -3.0
 * floor(-0.0);       // -0.0
 * floor(-Infinity);  // -1e309 i.e. -infinity in double type representation.
 */
static uc_value_t *
uc_floor(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_double_new(floor(x));
}

/**
 * Computes the smallest integer value not less than `x`.
 *
 * @function module:math#ceil
 *
 * @param {double} x number
 *
 * @returns {double}
 * Returns the smallest integer value not less than `x`, or `NaN` if the given
 * argument could not be converted to a number.
 * @example
 * ceil(2.7);        // 3.0
 * ceil(-2.7);       // -2.0
 * ceil(-0.0);       // -0.0
 * ceil(-Infinity);  // -1e309 i.e. -infinity in double type representation.
 */
static uc_value_t *
uc_ceil(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_double_new(ceil(x));
}

/**
 * Returns the integral value nearest to x rounding half-way cases away
 * from zero, regardless of the current rounding direction.
 *
 * @function module:math#round
 *
 * @param {double} x number
 *
 * @returns {double}
 * Returns the rounded integer value of `x`, or `NaN` if the given
 * argument could not be converted to a number.
 *
 * @example
 * round(2.4);        // 2.0
 * round(2.5);        // 3.0
 * round(2.7);        // 3.0
 * round(-2.4);       // -2.0
 * round(-2.5);       // -3.0
 * round(-2.7);       // -3.0
 * round(-0.0);       // -0.0
 * round(-Infinity);  // -1e309 i.e. -infinity in double type representation.
 */
static uc_value_t *
uc_round(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_double_new(round(x));
}

/**
 * Truncate away the decimal portion to produce the nearest integer not greater
 * in magnitude than x.
 *
 * @function module:math#trunc
 *
 * @param {double} x number
 *
 * @returns {double}
 * The integral portion remaining after the decimal portion is truncated, or
 * `NaN` if the given argument could not be converted to a number.
 *
 * @example
 * trunc(2.4);        // 2.0
 * trunc(2.5);        // 2.0
 * trunc(2.7);        // 2.0
 * trunc(-2.4);       // -2.0
 * trunc(-2.5);       // -2.0
 * trunc(-2.7);       // -2.0
 */
static uc_value_t *
uc_trunc(uc_vm_t *vm, size_t nargs)
{
	double x = ucv_to_double(uc_fn_arg(0));

	if (isnan(x))
		return ucv_double_new(NAN);

	return ucv_double_new(trunc(x));
}

static const uc_function_list_t math_fns[] = {
	{ "abs",		uc_abs },
	{ "acos",		uc_arccos },
	{ "asin",		uc_arcsin },
	{ "atan",		uc_arctan },
	{ "atan2",		uc_atan2 },
	{ "cosh",		uc_cosh },
	{ "sinh",		uc_sinh },
	{ "tanh",		uc_tanh },
	{ "tan",		uc_tan },
	{ "cos",		uc_cos },
	{ "exp",		uc_exp },
	{ "expm1",		uc_expm1 },
	{ "log",		uc_log },
	{ "log1p",		uc_log1p },
	{ "log10",		uc_log10 },
	{ "log2",		uc_log2 },
	{ "sin",		uc_sin },
	{ "sqrt",		uc_sqrt },
	{ "hypot",		uc_hypot },
	{ "cbrt",		uc_cbrt },
	{ "pow",		uc_pow },
	{ "rand",		uc_rand },
	{ "srand",		uc_srand },
	{ "isnan",		uc_isnan },
	{ "isinf",		uc_isinf },
	{ "deg2rad",	uc_deg2rad },
	{ "rad2deg",	uc_rad2deg },
	{ "fmin",		uc_fmin },
	{ "fmax",		uc_fmax },
	{ "clamp",		uc_clamp },
	{ "sign",		uc_sign },
	{ "signbit",	uc_signbit },
	{ "signnz",		uc_signnz },
	{ "copysign",	uc_copysign },
	{ "floor",		uc_floor },
	{ "ceil",		uc_ceil },
	{ "round",		uc_round },
	{ "trunc",		uc_trunc },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, math_fns);

	uc_vm_registry_set(vm, "math.srand_called", ucv_boolean_new(false));
}
