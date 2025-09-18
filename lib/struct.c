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

/**
 * # Handle Packed Binary Data
 *
 * The `struct` module provides routines for interpreting byte strings as packed
 * binary data.
 *
 * Functions can be individually imported and directly accessed using the
 * {@link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/import#named_import named import}
 * syntax:
 *
 *   ```
 *   import { pack, unpack } from 'struct';
 *
 *   let buffer = pack('bhl', -13, 1234, 444555666);
 *   let values = unpack('bhl', buffer);
 *   ```
 *
 * Alternatively, the module namespace can be imported
 * using a wildcard import statement:
 *
 *   ```
 *   import * as struct from 'struct';
 *
 *   let buffer = struct.pack('bhl', -13, 1234, 444555666);
 *   let values = struct.unpack('bhl', buffer);
 *   ```
 *
 * Additionally, the struct module namespace may also be imported by invoking
 * the `ucode` interpreter with the `-lstruct` switch.
 *
 * ## Format Strings
 *
 * Format strings describe the data layout when packing and unpacking data.
 * They are built up from format-characters, which specify the type of data
 * being packed/unpacked. In addition, special characters control the byte
 * order, size and alignment.
 *
 * Each format string consists of an optional prefix character which describes
 * the overall properties of the data and one or more format characters which
 * describe the actual data values and padding.
 *
 * ### Byte Order, Size, and Alignment
 *
 * By default, C types are represented in the machine's native format and byte
 * order, and properly aligned by skipping pad bytes if necessary (according to
 * the rules used by the C compiler).
 *
 * This behavior is chosen so that the bytes of a packed struct correspond
 * exactly to the memory layout of the corresponding C struct.
 *
 * Whether to use native byte ordering and padding or standard formats depends
 * on the application.
 *
 * Alternatively, the first character of the format string can be used to indicate
 * the byte order, size and alignment of the packed data, according to the
 * following table:
 *
 * | Character | Byte order             | Size     | Alignment |
 * |-----------|------------------------|----------|-----------|
 * | `@`       | native                 | native   | native    |
 * | `=`       | native                 | standard | none      |
 * | `<`       | little-endian          | standard | none      |
 * | `>`       | big-endian             | standard | none      |
 * | `!`       | network (= big-endian) | standard | none      |
 *
 * If the first character is not one of these, `'@'` is assumed.
 *
 * Native byte order is big-endian or little-endian, depending on the
 * host system. For example, Intel x86, AMD64 (x86-64), and Apple M1 are
 * little-endian; IBM z and many legacy architectures are big-endian.
 *
 * Native size and alignment are determined using the C compiler's
 * `sizeof` expression. This is always combined with native byte order.
 *
 * Standard size depends only on the format character; see the table in
 * the `format-characters` section.
 *
 * Note the difference between `'@'` and `'='`: both use native byte order,
 * but the size and alignment of the latter is standardized.
 *
 * The form `'!'` represents the network byte order which is always big-endian
 * as defined in `IETF RFC 1700`.
 *
 * There is no way to indicate non-native byte order (force byte-swapping); use
 * the appropriate choice of `'<'` or `'>'`.
 *
 * Notes:
 *
 * (1) Padding is only automatically added between successive structure members.
 *     No padding is added at the beginning or the end of the encoded struct.
 *
 * (2) No padding is added when using non-native size and alignment, e.g.
 *     with '<', '>', '=', and '!'.
 *
 * (3) To align the end of a structure to the alignment requirement of a
 *     particular type, end the format with the code for that type with a repeat
 *     count of zero.
 *
 *
 * ### Format Characters
 *
 * Format characters have the following meaning; the conversion between C and
 * ucode values should be obvious given their types.  The 'Standard size' column
 * refers to the size of the packed value in bytes when using standard size;
 * that is, when the format string starts with one of `'<'`, `'>'`, `'!'` or
 * `'='`.  When using native size, the size of the packed value is platform
 * dependent.
 *
 * | Format | C Type               | Ucode type | Standard size  | Notes    |
 * |--------|----------------------|------------|----------------|----------|
 * | `x`    | *pad byte*           | *no value* |                | (7)      |
 * | `c`    | `char`               | string     | 1              |          |
 * | `b`    | `signed char`        | int        | 1              | (1), (2) |
 * | `B`    | `unsigned char`      | int        | 1              | (2)      |
 * | `?`    | `_Bool`              | bool       | 1              | (1)      |
 * | `h`    | `short`              | int        | 2              | (2)      |
 * | `H`    | `unsigned short`     | int        | 2              | (2)      |
 * | `i`    | `int`                | int        | 4              | (2)      |
 * | `I`    | `unsigned int`       | int        | 4              | (2)      |
 * | `l`    | `long`               | int        | 4              | (2)      |
 * | `L`    | `unsigned long`      | int        | 4              | (2)      |
 * | `q`    | `long long`          | int        | 8              | (2)      |
 * | `Q`    | `unsigned long long` | int        | 8              | (2)      |
 * | `n`    | `ssize_t`            | int        |                | (3)      |
 * | `N`    | `size_t`             | int        |                | (3)      |
 * | `e`    | (6)                  | double     | 2              | (4)      |
 * | `f`    | `float`              | double     | 4              | (4)      |
 * | `d`    | `double`             | double     | 8              | (4)      |
 * | `s`    | `char[]`             | double     |                | (9)      |
 * | `p`    | `char[]`             | double     |                | (8)      |
 * | `P`    | `void *`             | int        |                | (5)      |
 * | `*`    | `char[]`             | string     |                | (10)     |
 * | `X`    | `char[]`             | string     |                | (11)     |
 * | `Z`    | `char[]`             | string     |                | (12)     |
 *
 * Notes:
 *
 * - (1) The `'?'` conversion code corresponds to the `_Bool` type defined by
 *    C99. If this type is not available, it is simulated using a `char`. In
 *    standard mode, it is always represented by one byte.
 *
 * - (2) When attempting to pack a non-integer using any of the integer
 *    conversion codes, this module attempts to convert the given value into an
 *    integer. If the value is not convertible, a type error exception is thrown.
 *
 * - (3) The `'n'` and `'N'` conversion codes are only available for the native
 *    size (selected as the default or with the `'@'` byte order character).
 *    For the standard size, you can use whichever of the other integer formats
 *    fits your application.
 *
 * - (4) For the `'f'`, `'d'` and `'e'` conversion codes, the packed
 *    representation uses the IEEE 754 binary32, binary64 or binary16 format
 *    (for `'f'`, `'d'` or `'e'` respectively), regardless of the floating-point
 *    format used by the platform.
 *
 * - (5) The `'P'` format character is only available for the native byte
 *    ordering (selected as the default or with the `'@'` byte order character).
 *    The byte order character `'='` chooses to use little- or big-endian
 *    ordering based on the host system. The struct module does not interpret
 *    this as native ordering, so the `'P'` format is not available.
 *
 * - (6) The IEEE 754 binary16 "half precision" type was introduced in the 2008
 *    revision of the `IEEE 754` standard. It has a sign bit, a 5-bit exponent
 *    and 11-bit precision (with 10 bits explicitly stored), and can represent
 *    numbers between approximately `6.1e-05` and `6.5e+04` at full precision.
 *    This type is not widely supported by C compilers: on a typical machine, an
 *    unsigned short can be used for storage, but not for math operations. See
 *    the Wikipedia page on the `half-precision floating-point format` for more
 *    information.
 *
 * - (7) When packing, `'x'` inserts one NUL byte.
 *
 * - (8) The `'p'` format character encodes a "Pascal string", meaning a short
 *    variable-length string stored in a *fixed number of bytes*, given by the
 *    count. The first byte stored is the length of the string, or 255,
 *    whichever is smaller.  The bytes of the string follow.  If the string
 *    passed in to `pack()` is too long (longer than the count minus 1), only
 *    the leading `count-1` bytes of the string are stored.  If the string is
 *    shorter than `count-1`, it is padded with null bytes so that exactly count
 *    bytes in all are used.  Note that for `unpack()`, the `'p'` format
 *    character consumes `count` bytes, but that the string returned can never
 *    contain more than 255 bytes.
 *
 * - (9) For the `'s'` format character, the count is interpreted as the length
 *    of the bytes, not a repeat count like for the other format characters; for
 *    example, `'10s'` means a single 10-byte string mapping to or from a single
 *    ucode byte string, while `'10c'` means 10 separate one byte character
 *    elements (e.g., `cccccccccc`) mapping to or from ten different ucode byte
 *    strings. If a count is not given, it defaults to 1. For packing, the
 *    string is truncated or padded with null bytes as appropriate to make it
 *    fit. For unpacking, the resulting bytes object always has exactly the
 *    specified number of bytes.  As a special case, `'0s'` means a single,
 *    empty string (while `'0c'` means 0 characters).
 *
 * - (10) The `*` format character serves as wildcard. For `pack()` it will
 *    append the corresponding byte argument string as-is, not applying any
 *    padding or zero filling. When a repeat count is given, that many bytes of
 *    the input byte string argument will be appended at most on `pack()`,
 *    effectively truncating longer input strings. For `unpack()`, the wildcard
 *    format will yield a byte string containing the entire remaining input data
 *    bytes, or - when a repeat count is given - that many bytes of input data
 *    at most.
 *
 * - (11) The `X` format character handles hexadecimal encoding of binary data.
 *    On `pack()`, the argument is a hexadecimal string; with no repeat count the
 *    entire string is decoded into binary, while a repeat count limits the
 *    number of output bytes (truncating longer input). On `unpack()`, the input
 *    binary data is converted into a hexadecimal string, using all remaining
 *    bytes by default, or at most the specified number of bytes when a repeat
 *    count is given. Decoding accepts both upper- and lowercase hex digits, but
 *    encoding always produces lowercase output. The encoded text length is
 *    exactly twice the number of processed binary bytes.
 *
 * - (12) The `Z` format character behaves like `X`, but uses base64 encoding
 *    instead of hexadecimal. On `pack()`, the argument is a base64 string; by
 *    default the entire string is decoded into binary, or at most the specified
 *    number of bytes when a repeat count is given. On `unpack()`, the input
 *    binary data is converted into a base64 string, consuming all remaining
 *    bytes by default, or at most the repeat count if given. The encoded base64
 *    string is approximately 1.4 times the size of the processed binary data.
 *
 * A format character may be preceded by an integral repeat count.  For example,
 * the format string `'4h'` means exactly the same as `'hhhh'`.
 *
 * Whitespace characters between formats are ignored; a count and its format
 * must not contain whitespace though.
 *
 * When packing a value `x` using one of the integer formats (`'b'`,
 * `'B'`, `'h'`, `'H'`, `'i'`, `'I'`, `'l'`, `'L'`,
 * `'q'`, `'Q'`), if `x` is outside the valid range for that format, a type
 * error exception is raised.
 *
 * For the `'?'` format character, the return value is either `true` or `false`.
 * When packing, the truish result value of the argument is used. Either 0 or 1
 * in the native or standard bool representation will be packed, and any
 * non-zero value will be `true` when unpacking.
 *
 * ## Examples
 *
 * Note:
 *    Native byte order examples (designated by the `'@'` format prefix or
 *    lack of any prefix character) may not match what the reader's
 *    machine produces as
 *    that depends on the platform and compiler.
 *
 * Pack and unpack integers of three different sizes, using big endian
 * ordering:
 *
 * ```
 * import { pack, unpack } from 'struct';
 *
 * pack(">bhl", 1, 2, 3);  // "\x01\x00\x02\x00\x00\x00\x03"
 * unpack(">bhl", "\x01\x00\x02\x00\x00\x00\x03");  // [ 1, 2, 3 ]
 * ```
 *
 * Attempt to pack an integer which is too large for the defined field:
 *
 * ```bash
 * $ ucode -lstruct -p 'struct.pack(">h", 99999)'
 * Type error: Format 'h' requires numeric argument between -32768 and 32767
 * In [-p argument], line 1, byte 24:
 *
 *  `struct.pack(">h", 99999)`
 *   Near here -------------^
 * ```
 *
 * Demonstrate the difference between `'s'` and `'c'` format characters:
 *
 * ```
 * import { pack } from 'struct';
 *
 * pack("@ccc", "1", "2", "3");  // "123"
 * pack("@3s", "123");           // "123"
 * ```
 *
 * The ordering of format characters may have an impact on size in native
 * mode since padding is implicit. In standard mode, the user is
 * responsible for inserting any desired padding.
 *
 * Note in the first `pack()` call below that three NUL bytes were added after
 * the packed `'#'` to align the following integer on a four-byte boundary.
 * In this example, the output was produced on a little endian machine:
 *
 * ```
 * import { pack } from 'struct';
 *
 * pack("@ci", "#", 0x12131415);  // "#\x00\x00\x00\x15\x14\x13\x12"
 * pack("@ic", 0x12131415, "#");  // "\x15\x14\x13\x12#"
 * ```
 *
 * The following format `'ih0i'` results in two pad bytes being added at the
 * end, assuming the platform's ints are aligned on 4-byte boundaries:
 *
 * ```
 * import { pack } from 'struct';
 *
 * pack("ih0i", 0x01010101, 0x0202);  // "\x01\x01\x01\x01\x02\x02\x00\x00"
 * ```
 *
 * Use the wildcard format to extract the remainder of the input data:
 *
 * ```
 * import { unpack } from 'struct';
 *
 * unpack("ccc*", "foobarbaz");   // [ "f", "o", "o", "barbaz" ]
 * unpack("ccc3*", "foobarbaz");  // [ "f", "o", "o", "bar" ]
 * ```
 *
 * Use the wildcard format to pack binary stings as-is into the result data:
 *
 * ```
 * import { pack } from 'struct';
 *
 * pack("h*h", 0x0101, "\x02\x00\x03", 0x0404);  // "\x01\x01\x02\x00\x03\x04\x04"
 * pack("c3*c", "a", "foobar", "c");  // "afooc"
 * ```
 *
 * @module struct
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <float.h>
#include <assert.h>

#include "ucode/module.h"
#include "ucode/vallist.h"

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

typedef struct {
	uc_resource_t resource;
	size_t length;
	size_t capacity;
	size_t position;
} formatbuffer_t;


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

#define double_pack64 uc_double_pack

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

#define double_unpack64 uc_double_unpack

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
	{ '*', sizeof(char), 0, NULL, NULL },
	{ 's', sizeof(char), 0, NULL, NULL },
	{ 'p', sizeof(char), 0, NULL, NULL },
	{ 'X', sizeof(char), 0, NULL, NULL },
	{ 'Z', sizeof(char), 0, NULL, NULL },
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
	{ '*', 1, 0, NULL, NULL },
	{ 's', 1, 0, NULL, NULL },
	{ 'p', 1, 0, NULL, NULL },
	{ 'X', 1, 0, NULL, NULL },
	{ 'Z', 1, 0, NULL, NULL },
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
	{ '*', 1, 0, NULL, NULL },
	{ 's', 1, 0, NULL, NULL },
	{ 'p', 1, 0, NULL, NULL },
	{ 'X', 1, 0, NULL, NULL },
	{ 'Z', 1, 0, NULL, NULL },
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
	ssize_t size, num, itemsize;
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
		else if (c == '*' || c == 'X' || c == 'Z')
			num = -1;
		else
			num = 1;

		e = lookup_table_entry(vm, c, f);

		if (e == NULL)
			return NULL;

		switch (c) {
		case '*': /* fall through */
		case 's':
		case 'p':
		case 'X':
		case 'Z':
			ncodes++;
			break;

		case 'x':
			break;

		default:
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

		size += (c != '*' && c != 'X' && c != 'Z') ? num * itemsize : 0;
	}

	/* check for overflow */
	if ((ncodes + 1) > ((size_t)SSIZE_MAX / sizeof(formatcode_t))) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Out of memory");

		return NULL;
	}

	state = xalloc(sizeof(*state) + ncodes * sizeof(formatcode_t));
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
		else if (c == '*' || c == 'X' || c == 'Z')
			num = -1;
		else
			num = 1;

		e = lookup_table_entry(vm, c, f);

		if (e == NULL)
			continue;

		size = align_for_entry(size, e);

		if (c == '*' || c == 's' || c == 'p' || c == 'X' || c == 'Z') {
			codes->offset = size;
			codes->size = num;
			codes->fmtdef = e;
			codes->repeat = 1;
			codes++;
			size += (c == 's' || c == 'p') ? num : 0;
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

static bool
grow_buffer(uc_vm_t *vm, void **buf, size_t *bufsz, size_t length)
{
	const size_t overhead = sizeof(uc_string_t) + 1;

	if (length > *bufsz) {
		size_t old_size = *bufsz;
		size_t new_size = (length + 7u) & ~7u;

		if (*buf != NULL) {
			new_size = *bufsz;

			while (length > new_size) {
				if (new_size > SIZE_MAX - (new_size >> 1)) {
					uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
						"Overflow reallocating buffer from %zu to %zu bytes",
						*bufsz, length);

					return false;
				}

				new_size += ((new_size >> 1) + 7u) & ~7u;
			}
		}

		char *tmp = realloc(*buf, new_size + overhead);

		if (!tmp) {
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
				"Error reallocating buffer to %zu+%zu bytes: %m",
				new_size, overhead);

			return false;
		}

		if (*buf)
			memset(tmp + overhead + old_size - 1, 0, new_size - old_size + 1);
		else
			memset(tmp, 0, new_size + overhead);

		*buf = tmp;
		*bufsz = new_size;
	}

	return true;
}

/* -------------------------------------------------------------------------
 * The following base64 encoding and decoding routines are taken from
 * https://git.openwrt.org/?p=project/libubox.git;a=blob;f=base64.c
 * and modified for use in ucode.
 *
 * Original copyright and license statements below.
 */

/*
 * base64 - libubox base64 functions
 *
 * Copyright (C) 2015 Felix Fietkau <nbd@openwrt.org>
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

/*	$OpenBSD: base64.c,v 1.7 2013/12/31 02:32:56 tedu Exp $	*/

/*
 * Copyright (c) 1996 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Portions Copyright (c) 1995 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * To the extent it has a right to do so, IBM grants an immunity from suit
 * under its patents, if any, for the use, sale or manufacture of products to
 * the extent that such products are used for performing Domain Name System
 * dynamic updates in TCP/IP networks by means of the Software.  No immunity is
 * granted for any product per se or for any other function of any product.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
 */

/* skips all whitespace anywhere.
   converts characters, four at a time, starting at (or after)
   src from base - 64 numbers into three 8 bit bytes in the target area.
   it returns the number of data bytes stored at the target, or -1 on error.
 */

static bool
b64dec(char *dest, size_t *dest_len, const char *src, size_t src_len,
       const char **errp)
{
	enum { BYTE1, BYTE2, BYTE3, BYTE4 } state = BYTE1;
	unsigned int ch = 0;
	size_t dest_off = 0;
	size_t src_off = 0;
	uint8_t val;

	for (; src_off < src_len; src_off++) {
		ch = (unsigned char)src[src_off];

		if (isspace(ch))	/* Skip whitespace anywhere. */
			continue;

		if (ch == '=' || dest_off >= *dest_len)
			break;

		if (ch >= 'A' && ch <= 'Z')
			val = ch - 'A';
		else if (ch >= 'a' && ch <= 'z')
			val = ch - 'a' + 26;
		else if (ch >= '0' && ch <= '9')
			val = ch - '0' + 52;
		else if (ch == '+')
			val = 62;
		else if (ch == '/')
			val = 63;
		else
			return *errp = "Invalid character", false;

		switch (state) {
		case BYTE1:
			dest[dest_off] = val << 2;
			state = BYTE2;
			break;

		case BYTE2:
			dest[dest_off++] |= val >> 4;
			dest[dest_off] = (val & 0x0f) << 4;
			state = BYTE3;
			break;

		case BYTE3:
			dest[dest_off++] |= val >> 2;
			dest[dest_off] = (val & 0x03) << 6;
			state = BYTE4;
			break;

		case BYTE4:
			dest[dest_off++] |= val;
			state = BYTE1;
			break;
		}
	}

	/*
	 * We are done decoding Base-64 chars.  Let's see if we ended
	 * on a byte boundary, and/or with erroneous trailing characters.
	 */

	if (ch == '=') {			/* We got a pad char. */
		if (src_off >= src_len)
			return *errp = "Invalid padding", false;

		src_off++;	/* Skip it, get next. */

		switch (state) {
		case BYTE1:		/* Invalid = in first position */
		case BYTE2:		/* Invalid = in second position */
			return false;

		case BYTE3:		/* Valid, means one byte of info */
			ch = 0;

			while (src_off < src_len) {
				ch = (unsigned char)src[src_off];

				if (!isspace(ch))
					break;
			}

			/* Make sure there is another trailing = sign. */
			if (ch != '=')
				return *errp = "Invalid padding", false;

			src_off++; /* Skip the = */

			/* Fall through to "single trailing =" case. */
			/* FALLTHROUGH */

		case BYTE4:		/* Valid, means two bytes of info */
			/*
			 * We know this char is an =.  Is there anything but
			 * whitespace after it?
			 */
			while (src_off < src_len)
				if (!isspace(src[src_off]))
					return *errp = "Trailing data", false;

			/*
			 * Now make sure for cases BYTE3 and BYTE4 that the "extra"
			 * bits that slopped past the last full byte were
			 * zeros.  If we don't check them, they become a
			 * subliminal channel.
			 */
			if (dest_off < *dest_len && dest[dest_off] != 0)
				return *errp = "Extraneous bits", false;
		}
	}
	else {
		/*
		 * We ended by seeing the end of the string.  Make sure we
		 * have no partial bytes lying around.
		 */
		if (state != BYTE1 && *dest_len == SIZE_MAX)
			return *errp = "Input string too long", false;
	}

	return *dest_len = dest_off, *errp = NULL, true;
}

static const char Base64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t
b64len(const char *src, size_t src_len)
{
	size_t padding_len = 0;
	size_t total_len = 0;
	size_t i = 0;

	for (; i < src_len; i++) {
		if (isspace(src[i]))
			continue;

		if ((src[i] >= 'A' && src[i] <= 'Z') ||
		    (src[i] >= 'a' && src[i] <= 'z') ||
		    (src[i] >= '0' && src[i] <= '9') ||
		    (src[i] == '+') || (src[i] == '/'))
			total_len++;
		else
			break;
	}

	for (; i < src_len; i++) {
		if (isspace(src[i]))
			continue;

		if (src[i] == '=')
			total_len++, padding_len++;
		else
			return 0;
	}

	if ((total_len % 4) != 0 || total_len < 4 || padding_len > 2)
		return 0;

	return (total_len / 4) * 3 - padding_len;
}

static uc_value_t *
b64enc(const char *src, size_t src_len)
{
	unsigned char input[3] = {0};
	uc_stringbuf_t *buf;
	char output[4];
	size_t i;

	buf = ucv_stringbuf_new();

	while (2 < src_len) {
		input[0] = (unsigned char)*src++;
		input[1] = (unsigned char)*src++;
		input[2] = (unsigned char)*src++;
		src_len -= 3;

		output[0] = Base64[input[0] >> 2];
		output[1] = Base64[((input[0] & 0x03) << 4) + (input[1] >> 4)];
		output[2] = Base64[((input[1] & 0x0f) << 2) + (input[2] >> 6)];
		output[3] = Base64[input[2] & 0x3f];

		ucv_stringbuf_addstr(buf, output, sizeof(output));
	}

	/* Now we worry about padding. */
	if (0 != src_len) {
		/* Get what's left. */
		input[0] = input[1] = input[2] = '\0';
		for (i = 0; i < src_len; i++)
			input[i] = *src++;

		output[0] = Base64[input[0] >> 2];
		output[1] = Base64[((input[0] & 0x03) << 4) + (input[1] >> 4)];
		output[2] = (src_len == 1) ? '=' : Base64[((input[1] & 0x0f) << 2) + (input[2] >> 6)];
		output[3] = '=';

		ucv_stringbuf_addstr(buf, output, sizeof(output));
	}

	return ucv_stringbuf_finish(buf);
}

static bool
uc_pack_common(uc_vm_t *vm, size_t nargs, formatstate_t *state, size_t argoff,
               void **buf, size_t *pos, size_t *capacity)
{
	size_t ncode, arg, off, new_pos;
	formatcode_t *code;
	ssize_t size, n;
	const void *p;

	for (ncode = 0, code = &state->codes[0], arg = argoff, off = 0;
	     ncode < state->ncodes;
	     code = &state->codes[++ncode]) {
		if (code->fmtdef->format == '*') {
			uc_value_t *v = uc_fn_arg(arg++);

			if (ucv_type(v) != UC_STRING)
				continue;

			n = ucv_string_length(v);

			if (code->size == -1 || code->size > n)
				off += n;
			else
				off += code->size;
		}
		else if (code->fmtdef->format == 'X') {
			uc_value_t *v = uc_fn_arg(arg++);

			if (ucv_type(v) != UC_STRING)
				continue;

			n = ucv_string_length(v) / 2;

			if (code->size == -1 || code->size > n)
				off += n;
			else
				off += code->size;
		}
		else if (code->fmtdef->format == 'Z') {
			uc_value_t *v = uc_fn_arg(arg++);

			if (ucv_type(v) != UC_STRING)
				continue;

			n = b64len(ucv_string_get(v), ucv_string_length(v));

			if (code->size == -1 || code->size > n)
				off += n;
			else
				off += code->size;
		}
		else {
			arg += code->repeat;
		}
	}

	new_pos = *pos + state->size + off;

	if (!grow_buffer(vm, buf, capacity, new_pos))
		return NULL;

	for (ncode = 0, code = &state->codes[0], off = 0;
	     ncode < state->ncodes;
	     code = &state->codes[++ncode]) {
		const formatdef_t *e = code->fmtdef;
		char *res = *buf + sizeof(uc_string_t) + *pos + code->offset + off;
		ssize_t j = code->repeat;

		while (j--) {
			uc_value_t *v = uc_fn_arg(argoff++);

			size = code->size;

			if (e->format == '*') {
				if (ucv_type(v) != UC_STRING) {
					uc_vm_raise_exception(vm, EXCEPTION_TYPE,
						"Argument for '*' must be a string");

					return false;
				}

				n = ucv_string_length(v);
				p = ucv_string_get(v);

				if (size == -1 || n < size)
					size = n;
				else if (n > size)
					n = size;

				off += size;

				if (n > 0)
					memcpy(res, p, n);
			}
			else if (e->format == 's') {
				if (ucv_type(v) != UC_STRING) {
					uc_vm_raise_exception(vm, EXCEPTION_TYPE,
						"Argument for 's' must be a string");

					return false;
				}

				n = ucv_string_length(v);
				p = ucv_string_get(v);

				if (n > size)
					n = size;

				if (n > 0)
					memcpy(res, p, n);
			}
			else if (e->format == 'p') {
				if (ucv_type(v) != UC_STRING) {
					uc_vm_raise_exception(vm, EXCEPTION_TYPE,
						"Argument for 'p' must be a string");

					return false;
				}

				n = ucv_string_length(v);
				p = ucv_string_get(v);

				if (n > (size - 1))
					n = size - 1;

				if (n > 0)
					memcpy(res + 1, p, n);

				if (n > 255)
					n = 255;

				*res = (unsigned char)n;
			}
			else if (e->format == 'X') {
				if (ucv_type(v) != UC_STRING) {
					uc_vm_raise_exception(vm, EXCEPTION_TYPE,
						"Argument for 'X' must be a string");

					return false;
				}

				n = ucv_string_length(v);
				p = ucv_string_get(v);

				if (n % 2) {
					uc_vm_raise_exception(vm, EXCEPTION_TYPE,
						"String length must be multiple of 2");

					return false;
				}

				if (size == -1 || n / 2 < size)
					size = n / 2;
				else if (n > size * 2)
					n = size * 2;

				for (ssize_t i = 0; i < n; i += 2) {
					uint8_t c1 = ((uint8_t *)p)[i + 0];
					uint8_t c2 = ((uint8_t *)p)[i + 1];

					if (!isxdigit(c1) || !isxdigit(c2)) {
						uc_vm_raise_exception(vm, EXCEPTION_TYPE,
							"Invalid hexadecimal string");

						return false;
					}

					c1 |= 32; c1 = (c1 >= 'a') ? 10 + c1 - 'a' : c1 - '0';
					c2 |= 32; c2 = (c2 >= 'a') ? 10 + c2 - 'a' : c2 - '0';

					((uint8_t *)res)[i >> 1] = (c1 << 4) | c2;
				}
			}
			else if (e->format == 'Z') {
				if (ucv_type(v) != UC_STRING) {
					uc_vm_raise_exception(vm, EXCEPTION_TYPE,
						"Argument for 'Z' must be a string");

					return false;
				}

				n = ucv_string_length(v);
				p = ucv_string_get(v);

				size_t len = (size == -1) ? SIZE_MAX : (size_t)size;
				const char *err = NULL;

				if (!b64dec(res, &len, p, n, &err)) {
					uc_vm_raise_exception(vm, EXCEPTION_TYPE,
						"Invalid base64 string: %s", err);

					return false;
				}

				if (size == -1 || len < (size_t)size)
					size = len;
			}
			else {
				if (!e->pack(vm, res, v, e))
					return false;
			}

			res += size;
		}
	}

	*pos = new_pos;

	return true;
}

static uc_value_t *
hexenc(const char *src, size_t src_len)
{
	uc_string_t *us = xalloc(sizeof(*us) + src_len * 2 + 1);
	const char *hexdigits = "0123456789abcdef";

	us->header.type = UC_STRING;
	us->header.refcount = 1;
	us->length = src_len * 2;

	for (size_t i = 0; i < src_len; i++) {
		uint8_t c = (uint8_t)src[i];

		us->str[(i << 1) + 0] = hexdigits[c >> 4];
		us->str[(i << 1) + 1] = hexdigits[c & 0x0f];
	}

	return &us->header;
}

static uc_value_t *
uc_unpack_common(uc_vm_t *vm, size_t nargs, formatstate_t *state,
                 const char *buf, long long pos, size_t *rem, bool single)
{
	uc_value_t *result;
	formatcode_t *code;
	size_t ncode, off;
	ssize_t size, n;

	if (pos < 0)
		pos += *rem;

	if (pos < 0 || (size_t)pos >= *rem)
		return NULL;

	buf += pos;
	*rem -= pos;

	result = single ? NULL : ucv_array_new(vm);

	for (ncode = 0, code = &state->codes[0], off = 0;
	     ncode < state->ncodes;
	     code = &state->codes[++ncode]) {
		const formatdef_t *e = code->fmtdef;
		const char *res = buf + code->offset + off;
		ssize_t j = code->repeat;

		while (j--) {
			uc_value_t *v = NULL;

			size = code->size;

			if (e->format == '*' || e->format == 'X' || e->format == 'Z') {
				if (size == -1 || (size_t)size > *rem)
					size = *rem;

				off += size;
			}
			else if (size >= 0 && (size_t)size > *rem) {
				goto fail;
			}

			if (e->format == 's' || e->format == '*') {
				v = ucv_string_new_length(res, size);
			}
			else if (e->format == 'p') {
				n = *(unsigned char *)res;

				if (n >= size)
					n = (size > 0 ? size - 1 : 0);

				v = ucv_string_new_length(res + 1, n);
			}
			else if (e->format == 'X') {
				v = hexenc(res, size);
			}
			else if (e->format == 'Z') {
				v = b64enc(res, size);
			}
			else {
				v = e->unpack(vm, res, e);
			}

			if (v == NULL)
				goto fail;

			res += size;
			*rem -= size;

			if (single)
				return v;

			ucv_array_push(result, v);
		}
	}

	return result;

fail:
	ucv_put(result);

	return NULL;
}


/**
 * Pack given values according to specified format.
 *
 * The `pack()` function creates a byte string containing the argument values
 * packed according to the given format string.
 *
 * Returns the packed string.
 *
 * Raises a runtime exception if a given argument value does not match the
 * required type of the corresponding format string directive or if and invalid
 * format string is provided.
 *
 * @function module:struct#pack
 *
 * @param {string} format
 * The format string.
 *
 * @param {...*} values
 * Variable number of values to pack.
 *
 * @returns {string}
 *
 * @example
 * // Pack the values 1, 2, 3 as three consecutive unsigned int values
 * // in network byte order.
 * const data = pack('!III', 1, 2, 3);
 */
static uc_value_t *
uc_pack(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *fmtval = uc_fn_arg(0);
	size_t pos = 0, capacity = 0;
	uc_string_t *us = NULL;
	formatstate_t *state;

	state = parse_format(vm, fmtval);

	if (!state)
		return NULL;

	if (!uc_pack_common(vm, nargs, state, 1, (void **)&us, &pos, &capacity)) {
		free(state);
		free(us);

		return NULL;
	}

	free(state);

	us->header.type = UC_STRING;
	us->header.refcount = 1;
	us->length = pos;

	return &us->header;
}

/**
 * Unpack given byte string according to specified format.
 *
 * The `unpack()` function interpretes a byte string according to the given
 * format string and returns the resulting values. If the optional offset
 * argument is given, unpacking starts from this byte position within the input.
 * If not specified, the start offset defaults to `0`, the start of the given
 * input string.
 *
 * Returns an array of unpacked values.
 *
 * Raises a runtime exception if the format string is invalid or if an invalid
 * input string or offset value is given.
 *
 * @function module:struct#unpack
 *
 * @param {string} format
 * The format string.
 *
 * @param {string} input
 * The input string to unpack.
 *
 * @param {number} [offset=0]
 * The offset within the input string to start unpacking from.
 *
 * @returns {array}
 *
 * @example
 * // Unpack three consecutive unsigned int values in network byte order.
 * const numbers =
 *   unpack('!III', '\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03');
 * print(numbers, "\n"); // [ 1, 2, 3 ]
 */
static uc_value_t *
uc_unpack(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *fmtval = uc_fn_arg(0);
	uc_value_t *bufval = uc_fn_arg(1);
	uc_value_t *offset = uc_fn_arg(2);
	uc_value_t *res = NULL;
	formatstate_t *state;
	long long pos = 0;
	size_t rem;
	char *buf;

	if (ucv_type(bufval) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			"Buffer value not a string");

		return NULL;
	}

	if (offset && !ucv_as_longlong(vm, offset, &pos))
		return NULL;

	state = parse_format(vm, fmtval);

	if (!state)
		return NULL;

	buf = ucv_string_get(bufval);
	rem = ucv_string_length(bufval);
	res = uc_unpack_common(vm, nargs, state, buf, pos, &rem, false);

	free(state);

	return res;
}


/**
 * Represents a struct instance created by `new()`.
 *
 * @class module:struct.instance
 * @hideconstructor
 *
 * @see {@link module:struct#new|new()}
 *
 * @example
 *
 * const fmt = struct.new(…);
 *
 * fmt.pack(…);
 *
 * const values = fmt.unpack(…);
 */

/**
 * Precompile format string.
 *
 * The `new()` function precompiles the given format string argument and returns
 * a `struct` object instance useful for packing and unpacking multiple items
 * without having to recompute the internal format each time.
 *
 * Returns an precompiled struct format instance.
 *
 * Raises a runtime exception if the format string is invalid.
 *
 * @function module:struct#new
 *
 * @param {string} format
 * The format string.
 *
 * @returns {module:struct.instance}
 *
 * @example
 * // Create a format of three consecutive unsigned int values in network byte order.
 * const fmt = struct.new('!III');
 * const buf = fmt.pack(1, 2, 3);  // "\x00\x00\x00\x01…"
 * print(fmt.unpack(buf), "\n");   // [ 1, 2, 3 ]
 */
static uc_value_t *
uc_struct_new(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *fmtval = uc_fn_arg(0);
	formatstate_t *state;

	state = parse_format(vm, fmtval);

	if (!state)
		return NULL;

	return ucv_resource_create(vm, "struct.format", state);
}

/**
 * Pack given values.
 *
 * The `pack()` function creates a byte string containing the argument values
 * packed according to the given format instance.
 *
 * Returns the packed string.
 *
 * Raises a runtime exception if a given argument value does not match the
 * required type of the corresponding format string directive.
 *
 * @function module:struct.instance#pack
 *
 * @param {...*} values
 * Variable number of values to pack.
 *
 * @returns {string}
 *
 * @example
 * const fmt = struct.new(…);
 * const data = fmt.pack(…);
 */
static uc_value_t *
uc_struct_pack(uc_vm_t *vm, size_t nargs)
{
	formatstate_t **state = uc_fn_this("struct.format");
	size_t pos = 0, capacity = 0;
	uc_string_t *us = NULL;

	if (!state || !*state)
		return NULL;

	if (!uc_pack_common(vm, nargs, *state, 0, (void **)&us, &pos, &capacity)) {
		free(us);

		return NULL;
	}

	us->header.type = UC_STRING;
	us->header.refcount = 1;
	us->length = pos;

	return &us->header;
}

/**
 * Unpack given byte string.
 *
 * The `unpack()` function interpretes a byte string according to the given
 * format instance and returns the resulting values. If the optional offset
 * argument is given, unpacking starts from this byte position within the input.
 * If not specified, the start offset defaults to `0`, the start of the given
 * input string.
 *
 * Returns an array of unpacked values.
 *
 * Raises a runtime exception if an invalid input string or offset value is
 * given.
 *
 * @function module:struct.instance#unpack
 *
 * @param {string} input
 * The input string to unpack.
 *
 * @param {number} [offset=0]
 * The offset within the input string to start unpacking from.
 *
 * @returns {array}
 *
 * @example
 * const fmt = struct.new(…);
 * const values = fmt.unpack(…);
 */
static uc_value_t *
uc_struct_unpack(uc_vm_t *vm, size_t nargs)
{
	formatstate_t **state = uc_fn_this("struct.format");
	uc_value_t *bufval = uc_fn_arg(0);
	uc_value_t *offset = uc_fn_arg(1);
	long long pos = 0;
	size_t rem;
	char *buf;

	if (!state || !*state)
		return NULL;

	if (ucv_type(bufval) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			"Buffer value not a string");

		return NULL;
	}

	if (offset && !ucv_as_longlong(vm, offset, &pos))
		return NULL;

	buf = ucv_string_get(bufval);
	rem = ucv_string_length(bufval);

	return uc_unpack_common(vm, nargs, *state, buf, pos, &rem, false);
}


/**
 * Represents a struct buffer instance created by `buffer()`.
 *
 * @class module:struct.buffer
 * @hideconstructor
 *
 * @see {@link module:struct#buffer|buffer()}
 *
 * @example
 *
 * const buf = struct.buffer();
 *
 * buf.put('I', 12345);
 *
 * const value = buf.get('I');
 */

/**
 * Creates a new struct buffer instance.
 *
 * The `buffer()` function creates a new struct buffer object that can be used
 * for incremental packing and unpacking of binary data. If an initial data
 * string is provided, the buffer is initialized with this content.
 *
 * Note that even when initial data is provided, the buffer position is always
 * set to zero. This design assumes that the primary intent when initializing
 * a buffer with data is to read (unpack) from the beginning. If you want to
 * append data to a pre-initialized buffer, you need to explicitly move the
 * position to the end, either by calling `end()` or by setting the position
 * manually with `pos()`.
 *
 * Returns a new struct buffer instance.
 *
 * @function module:struct#buffer
 *
 * @param {string} [initialData]
 * Optional initial data to populate the buffer with.
 *
 * @returns {module:struct.buffer}
 *
 * @example
 * // Create an empty buffer
 * const emptyBuf = struct.buffer();
 *
 * // Create a buffer with initial data
 * const dataBuf = struct.buffer("\x01\x02\x03\x04");
 *
 * // Read from the beginning of the initialized buffer
 * const value = dataBuf.get('I');
 *
 * // Append data to the initialized buffer
 * dataBuf.end().put('I', 5678);
 *
 * // Alternative chained syntax for initializing and appending
 * const buf = struct.buffer("\x01\x02\x03\x04").end().put('I', 5678);
 */
static uc_value_t *
uc_fmtbuf_new(uc_vm_t *vm, size_t nargs)
{
	formatbuffer_t *buffer = xalloc(sizeof(*buffer));
	uc_value_t *init_data = uc_fn_arg(0);

	buffer->resource.header.type = UC_RESOURCE;
	buffer->resource.header.refcount = 1;
	buffer->resource.type = ucv_resource_type_lookup(vm, "struct.buffer");

	if (ucv_type(init_data) == UC_STRING)  {
		char *buf = ucv_string_get(init_data);
		size_t len = ucv_string_length(init_data);

		if (!grow_buffer(vm, &buffer->resource.data, &buffer->capacity, len)) {
			free(buffer);

			return NULL;
		}

		buffer->length = len;
		memcpy((char *)buffer->resource.data + sizeof(uc_string_t), buf, len);
	}

	return &buffer->resource.header;
}

static formatbuffer_t *
formatbuffer_ctx(uc_vm_t *vm)
{
	uc_value_t *ctx = vm->callframes.entries[vm->callframes.count - 1].ctx;

	if (ucv_type(ctx) != UC_RESOURCE)
		return NULL;

	uc_resource_t *res = (uc_resource_t *)ctx;

	if (!res->type || strcmp(res->type->name, "struct.buffer") != 0)
		return NULL;

	return (formatbuffer_t *)res;
}

/**
 * Get or set the current position in the buffer.
 *
 * If called without arguments, returns the current position.
 * If called with a position argument, sets the current position to that value.
 *
 * @function module:struct.buffer#pos
 *
 * @param {number} [position]
 * The position to set. If omitted, the current position is returned.
 *
 * @returns {number|module:struct.buffer}
 * If called without arguments, returns the current position.
 * If called with a position argument, returns the buffer instance for chaining.
 *
 * @example
 * const currentPos = buf.pos();
 * buf.pos(10);  // Set position to 10
 */
static uc_value_t *
uc_fmtbuf_pos(uc_vm_t *vm, size_t nargs)
{
	formatbuffer_t *buffer = formatbuffer_ctx(vm);
	uc_value_t *new_pos = uc_fn_arg(0);

	if (!buffer)
		return NULL;

	if (new_pos) {
		long long pos;

		if (!ucv_as_longlong(vm, new_pos, &pos))
			return NULL;

		if (pos < 0) pos += buffer->length;
		if (pos < 0) pos = 0;

		if (!grow_buffer(vm, &buffer->resource.data, &buffer->capacity, pos))
			return NULL;

		buffer->position = pos;

		if (buffer->position > buffer->length)
			buffer->length = buffer->position;

		return ucv_get(&buffer->resource.header);
	}

	return ucv_uint64_new(buffer->position);
}

/**
 * Get or set the current buffer length.
 *
 * If called without arguments, returns the current length of the buffer.
 * If called with a length argument, sets the buffer length to that value,
 * padding the data with trailing zero bytes or truncating it depending on
 * whether the updated length is larger or smaller than the current length
 * respectively.
 *
 * In case the updated length is smaller than the current buffer offset, the
 * position is updated accordingly, so that it points to the new end of the
 * truncated buffer data.
 *
 * @function module:struct.buffer#length
 *
 * @param {number} [length]
 * The length to set. If omitted, the current length is returned.
 *
 * @returns {number|module:struct.buffer}
 * If called without arguments, returns the current length.
 * If called with a length argument, returns the buffer instance for chaining.
 *
 * @example
 * const buf = struct.buffer("abc"); // Initialize buffer with three bytes
 * const currentLen = buf.length();  // Returns 3
 *
 * buf.length(6);                    // Extend to 6 bytes
 * buf.slice();                      // Trailing null bytes: "abc\x00\x00\x00"
 *
 * buf.length(2);                    // Truncate to 2 bytes
 * buf.slice();                      // Truncated data: "ab"
 */
static uc_value_t *
uc_fmtbuf_length(uc_vm_t *vm, size_t nargs)
{
	formatbuffer_t *buffer = formatbuffer_ctx(vm);
	uc_value_t *new_len = uc_fn_arg(0);

	if (!buffer)
		return NULL;

	if (new_len) {
		size_t len;

		if (!ucv_as_size_t(vm, new_len, &len))
			return NULL;

		if (len > buffer->length) {
			if (!grow_buffer(vm, &buffer->resource.data, &buffer->capacity, len))
				return NULL;

			buffer->length = len;
		}
		else if (len < buffer->length) {
			memset((char *)buffer->resource.data + sizeof(uc_string_t) + len,
				0, buffer->length - len);

			buffer->length = len;

			if (len < buffer->position)
				buffer->position = len;
		}

		return ucv_get(&buffer->resource.header);
	}

	return ucv_uint64_new(buffer->length);
}

/**
 * Set the buffer position to the start (0).
 *
 * @function module:struct.buffer#start
 *
 * @returns {module:struct.buffer}
 * The buffer instance.
 *
 * @example
 * buf.start();
 */
static uc_value_t *
uc_fmtbuf_start(uc_vm_t *vm, size_t nargs)
{
	formatbuffer_t *buffer = formatbuffer_ctx(vm);

	if (!buffer)
		return NULL;

	buffer->position = 0;

	return ucv_get(&buffer->resource.header);
}

/**
 * Set the buffer position to the end.
 *
 * @function module:struct.buffer#end
 *
 * @returns {module:struct.buffer}
 * The buffer instance.
 *
 * @example
 * buf.end();
 */
static uc_value_t *
uc_fmtbuf_end(uc_vm_t *vm, size_t nargs)
{
	formatbuffer_t *buffer = formatbuffer_ctx(vm);

	if (!buffer)
		return NULL;

	buffer->position = buffer->length;

	return ucv_get(&buffer->resource.header);
}

/**
 * Pack data into the buffer at the current position.
 *
 * The `put()` function packs the given values into the buffer according to
 * the specified format string, starting at the current buffer position.
 * The format string follows the same syntax as used in `struct.pack()`.
 *
 * For a detailed explanation of the format string syntax, refer to the
 * ["Format Strings" section]{@link module:struct} in the module
 * documentation.
 *
 * @function module:struct.buffer#put
 *
 * @param {string} format
 * The format string specifying how to pack the data.
 *
 * @param {...*} values
 * The values to pack into the buffer.
 *
 * @returns {module:struct.buffer}
 * The buffer instance.
 *
 * @see {@link module:struct#pack|struct.pack()}
 *
 * @example
 * buf.put('II', 1234, 5678);
 */
static uc_value_t *
uc_fmtbuf_put(uc_vm_t *vm, size_t nargs)
{
	formatbuffer_t *buffer = formatbuffer_ctx(vm);
	uc_value_t *fmt = uc_fn_arg(0);
	formatstate_t *state;
	bool res;

	if (!buffer)
		return NULL;

	state = parse_format(vm, fmt);

	if (!state)
		return NULL;

	res = uc_pack_common(vm, nargs, state, 1,
		&buffer->resource.data, &buffer->position, &buffer->capacity);

	free(state);

	if (!res)
		return NULL;

	if (buffer->position > buffer->length)
		buffer->length = buffer->position;

	return ucv_get(&buffer->resource.header);
}

static uc_value_t *
fmtbuf_get_common(uc_vm_t *vm, size_t nargs, bool single)
{
	formatbuffer_t *buffer = formatbuffer_ctx(vm);
	uc_value_t *fmt = uc_fn_arg(0);
	formatstate_t *state;
	uc_value_t *result;
	size_t rem;
	char *buf;

	if (!buffer)
		return NULL;

	if (single && ucv_type(fmt) == UC_INTEGER) {
		int64_t len = ucv_int64_get(fmt);

		if (errno != 0)
			goto ebounds;

		size_t spos, epos;

		if (len < 0) {
			if (len == INT64_MIN)
				goto ebounds;

			if ((uint64_t)-len > buffer->position)
				return NULL;

			spos = buffer->position + len;
			epos = buffer->position;
		}
		else {
			if ((uint64_t)len > (SIZE_MAX - buffer->position))
				goto ebounds;

			if (buffer->position + len > buffer->length)
				return NULL;

			spos = buffer->position;
			epos = buffer->position + len;

			buffer->position = epos;
		}

		return ucv_string_new_length(
			(char *)buffer->resource.data + sizeof(uc_string_t) + spos,
			epos - spos);

ebounds:
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			"Length value out of bounds");

		return NULL;
	}

	state = parse_format(vm, fmt);

	if (!state)
		return NULL;

	if (single && (state->ncodes != 1 || state->codes[0].repeat != 1)) {
		free(state);
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			"get() expects a format string for a single value. "
			"Use read() for multiple values.");

		return NULL;
	}

	rem = buffer->length;
	buf = (char *)buffer->resource.data + sizeof(uc_string_t);

	result = uc_unpack_common(vm, nargs, state,
		buf, buffer->position, &rem, single);

	if (result)
		buffer->position = buffer->length - rem;

	free(state);

	return result;
}

/**
 * Unpack a single value from the buffer at the current position.
 *
 * The `get()` function unpacks a single value from the buffer according to the
 * specified format string, starting at the current buffer position.
 * The format string follows the same syntax as used in `struct.unpack()`.
 *
 * For a detailed explanation of the format string syntax, refer to the
 * ["Format Strings" section]{@link module:struct} in the module documentation.
 *
 * Alternatively, `get()` accepts a postive or negative integer as format, which
 * specifies the length of a string to unpack before or after the current
 * position. Negative values extract that many bytes before the current offset
 * while postive ones extracts that many bytes after.
 *
 * @function module:struct.buffer#get
 *
 * @param {string|number} format
 * The format string specifying how to unpack the data.
 *
 * @returns {*}
 * The unpacked value.
 *
 * @see {@link module:struct#unpack|struct.unpack()}
 *
 * @example
 * const val = buf.get('I');
 * const str = buf.get(5);    // equivalent to buf.get('5s')
 * const str = buf.get(-3);   // equivalent to buf.pos(buf.pos() - 3).get('3s')
 */
static uc_value_t *
uc_fmtbuf_get(uc_vm_t *vm, size_t nargs)
{
	return fmtbuf_get_common(vm, nargs, true);
}

/**
 * Unpack multiple values from the buffer at the current position.
 *
 * The `read()` function unpacks multiple values from the buffer according to
 * the specified format string, starting at the current buffer position.
 * The format string follows the same syntax as used in `struct.unpack()`.
 *
 * For a detailed explanation of the format string syntax, refer to the
 * ["Format Strings" section]{@link module:struct} in the module documentation.
 *
 * @function module:struct.buffer#get
 *
 * @param {string} format
 * The format string specifying how to unpack the data.
 *
 * @returns {array}
 * An array containing the unpacked values.
 *
 * @see {@link module:struct#unpack|struct.unpack()}
 *
 * @example
 * const values = buf.get('II');
 */
static uc_value_t *
uc_fmtbuf_read(uc_vm_t *vm, size_t nargs)
{
	return fmtbuf_get_common(vm, nargs, false);
}

/**
 * Extract a slice of the buffer content.
 *
 * The `slice()` function returns a substring of the buffer content
 * between the specified start and end positions.
 *
 * Both the start and end position values may be negative, in which case they're
 * relative to the end of the buffer, e.g. `slice(-3)` will extract the last
 * three bytes of data.
 *
 * @function module:struct.buffer#slice
 *
 * @param {number} [start=0]
 * The starting position of the slice.
 *
 * @param {number} [end=buffer.length()]
 * The ending position of the slice (exclusive).
 *
 * @returns {string}
 * A string containing the specified slice of the buffer content.
 *
 * @example
 * const slice = buf.slice(4, 8);
 */
static uc_value_t *
uc_fmtbuf_slice(uc_vm_t *vm, size_t nargs)
{
	formatbuffer_t *buffer = formatbuffer_ctx(vm);
	uc_value_t *from = uc_fn_arg(0);
	uc_value_t *to = uc_fn_arg(1);
	long long spos, epos;
	char *buf;

	if (!buffer)
		return NULL;

	spos = 0;
	epos = buffer->length;

	if (from && !ucv_as_longlong(vm, from, &spos))
		return NULL;

	if (to && !ucv_as_longlong(vm, to, &epos))
		return NULL;

	if (spos < 0) spos += buffer->length;
	if (spos < 0) spos = 0;
	if ((unsigned long long)spos > buffer->length) spos = buffer->length;

	if (epos < 0) epos += buffer->length;
	if (epos < spos) epos = spos;
	if ((unsigned long long)epos > buffer->length) epos = buffer->length;

	buf = (char *)buffer->resource.data + sizeof(uc_string_t) + spos;

	return ucv_string_new_length(buf, epos - spos);
}

/**
 * Set a slice of the buffer content to given byte value.
 *
 * The `set()` function overwrites a substring of the buffer content with the
 * given byte value, similar to the C `memset()` function, between the specified
 * start and end positions.
 *
 * Both the start and end position values may be negative, in which case they're
 * relative to the end of the buffer, e.g. `set(0, -2)` will overwrite the last
 * two bytes of data with `\x00`.
 *
 * When the start or end positions are beyond the current buffer length, the
 * buffer is grown accordingly.
 *
 * @function module:struct.buffer#set
 *
 * @param {number|string} [value=0]
 * The byte value to use when overwriting buffer contents. When a string is
 * given, the first character is used as value.
 *
 * @param {number} [start=0]
 * The position to start overwriting from.
 *
 * @param {number} [end=buffer.length()]
 * The position to end overwriting (exclusive).
 *
 * @returns {module:struct.buffer}
 * The buffer instance.
 *
 * @example
 * const buf = struct.buffer("abcde");
 * buf.set("X", 2, 4).slice();  // Buffer content is now "abXXe"
 * buf.set().slice();           // Buffer content is now "\x00\x00\x00\x00\x00"
 */
static uc_value_t *
uc_fmtbuf_set(uc_vm_t *vm, size_t nargs)
{
	formatbuffer_t *buffer = formatbuffer_ctx(vm);
	uc_value_t *byte = uc_fn_arg(0);
	uc_value_t *from = uc_fn_arg(1);
	uc_value_t *to = uc_fn_arg(2);
	long long spos, epos;
	long bval;

	if (!buffer)
		return NULL;

	bval = 0;
	spos = 0;
	epos = buffer->length;

	if (ucv_type(byte) == UC_STRING)
		bval = *ucv_string_get(byte);
	else if (byte && !ucv_as_long(vm, byte, &bval))
		return NULL;

	if (from && !ucv_as_longlong(vm, from, &spos))
		return NULL;

	if (to && !ucv_as_longlong(vm, to, &epos))
		return NULL;

	if (spos < 0) spos += buffer->length;
	if (spos < 0) spos = 0;

	if (epos < 0) epos += buffer->length;

	if (epos > spos) {
		if ((unsigned long long)epos > buffer->length) {
			if (!grow_buffer(vm, &buffer->resource.data, &buffer->capacity, epos))
				return NULL;

			buffer->length = epos;
		}

		memset((char *)buffer->resource.data + sizeof(uc_string_t) + spos,
			bval, epos - spos);
	}

	return ucv_get(&buffer->resource.header);
}

/**
 * Extract and remove all content from the buffer.
 *
 * The `pull()` function returns all content of the buffer as a string
 * and resets the buffer to an empty state.
 *
 * @function module:struct.buffer#pull
 *
 * @returns {string}
 * A string containing all the buffer content.
 *
 * @example
 * const allData = buf.pull();
 */
static uc_value_t *
uc_fmtbuf_pull(uc_vm_t *vm, size_t nargs)
{
	formatbuffer_t *buffer = formatbuffer_ctx(vm);
	uc_string_t *us;

	if (!buffer)
		return NULL;

	if (!buffer->resource.data)
		return ucv_string_new_length("", 0);

	us = buffer->resource.data;
	us->header.type = UC_STRING;
	us->header.refcount = 1;
	us->length = buffer->length;

	buffer->resource.data = NULL;
	buffer->capacity = 0;
	buffer->position = 0;
	buffer->length = 0;

	return &us->header;
}


static const uc_function_list_t struct_inst_fns[] = {
	{ "pack",	uc_struct_pack },
	{ "unpack",	uc_struct_unpack }
};

static const uc_function_list_t buffer_inst_fns[] = {
	{ "pos",	uc_fmtbuf_pos },
	{ "length", uc_fmtbuf_length },
	{ "start",	uc_fmtbuf_start },
	{ "end",	uc_fmtbuf_end },
	{ "set",	uc_fmtbuf_set },
	{ "put",	uc_fmtbuf_put },
	{ "get",	uc_fmtbuf_get },
	{ "read",	uc_fmtbuf_read },
	{ "slice",	uc_fmtbuf_slice },
	{ "pull",	uc_fmtbuf_pull },
};

static const uc_function_list_t struct_fns[] = {
	{ "pack",	uc_pack },
	{ "unpack",	uc_unpack },
	{ "new",	uc_struct_new },
	{ "buffer",	uc_fmtbuf_new }
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	optimize_functions();

	uc_function_list_register(scope, struct_fns);

	uc_type_declare(vm, "struct.format", struct_inst_fns, free);
	uc_type_declare(vm, "struct.buffer", buffer_inst_fns, free);
}
