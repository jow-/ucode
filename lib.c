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
 * # Builtin functions
 *
 * The core namespace is not an actual module but refers to the set of
 * builtin functions and properties available to `ucode` scripts.
 *
 * @module core
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <time.h>
#include <dlfcn.h>
#include <libgen.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fnmatch.h>
#include <assert.h>

#include "json-c-compat.h"

#include "ucode/lexer.h"
#include "ucode/compiler.h"
#include "ucode/vm.h"
#include "ucode/lib.h"
#include "ucode/source.h"
#include "ucode/program.h"
#include "ucode/platform.h"

static void
format_context_line(uc_stringbuf_t *buf, const char *line, size_t off, bool compact)
{
	unsigned padlen, i;
	const char *p;

	for (p = line, padlen = 0; *p != '\n' && *p != '\0'; p++) {
		if (compact && (p - line) == (ptrdiff_t)off)
			ucv_stringbuf_append(buf, "\033[22m");

		switch (*p) {
		case '\t':
			ucv_stringbuf_append(buf, "    ");
			if (p < line + off)
				padlen += 4;
			break;

		case '\r':
		case '\v':
			ucv_stringbuf_append(buf, " ");
			if (p < line + off)
				padlen++;
			break;

		default:
			ucv_stringbuf_addstr(buf, p, 1);
			if (p < line + off)
				padlen++;
		}
	}

	if (compact) {
		ucv_stringbuf_append(buf, "\033[m\n");

		return;
	}

	ucv_stringbuf_append(buf, "`\n  ");

	if (padlen < strlen("Near here ^")) {
		for (i = 0; i < padlen; i++)
			ucv_stringbuf_append(buf, " ");

		ucv_stringbuf_append(buf, "^-- Near here\n");
	}
	else {
		ucv_stringbuf_append(buf, "Near here ");

		for (i = strlen("Near here "); i < padlen; i++)
			ucv_stringbuf_append(buf, "-");

		ucv_stringbuf_append(buf, "^\n");
	}
}

static char *
source_filename(uc_source_t *src, uint32_t line)
{
	const char *name = src->filename ? basename(src->filename) : "[?]";
	static char buf[sizeof("xxxxxxxxx.uc:0000000000")];
	size_t len = strlen(name);

	if (len > 12)
		snprintf(buf, sizeof(buf), "...%s:%u", name + (len - 9), line);
	else
		snprintf(buf, sizeof(buf), "%12s:%u", name, line);

	return buf;
}

bool
uc_source_context_format(uc_stringbuf_t *buf, uc_source_t *src, size_t off, bool compact)
{
	size_t len, rlen;
	bool truncated;
	char line[256];
	long srcpos;
	int eline;

	srcpos = ftell(src->fp);

	if (srcpos == -1)
		return false;

	fseek(src->fp, 0, SEEK_SET);

	truncated = false;
	eline = 1;
	rlen = 0;

	while (fgets(line, sizeof(line), src->fp)) {
		len = strlen(line);
		rlen += len;

		if (rlen >= off) {
			if (compact)
				ucv_stringbuf_printf(buf, "\033[2;40;97m%17s  %s",
					source_filename(src, eline),
					truncated ? "..." : "");
			else
				ucv_stringbuf_printf(buf, "\n `%s",
					truncated ? "..." : "");

			format_context_line(buf, line, len - (rlen - off) + (truncated ? 3 : 0), compact);
			break;
		}

		truncated = (len > 0 && line[len-1] != '\n');
		eline += !truncated;
	}

	fseek(src->fp, srcpos, SEEK_SET);

	return true;
}

bool
uc_error_context_format(uc_stringbuf_t *buf, uc_source_t *src, uc_value_t *stacktrace, size_t off)
{
	uc_value_t *e, *fn, *file, *line, *byte;
	const char *path;
	size_t idx;

	for (idx = 0; idx < (stacktrace ? ucv_array_length(stacktrace) : 0); idx++) {
		e = ucv_array_get(stacktrace, idx);
		fn = ucv_object_get(e, "function", NULL);
		file = ucv_object_get(e, "filename", NULL);

		if (idx == 0) {
			path = (file && strcmp(ucv_string_get(file), "[stdin]"))
				? ucv_string_get(file) : NULL;

			if (path && fn)
				ucv_stringbuf_printf(buf, "In %s(), file %s, ", ucv_string_get(fn), path);
			else if (fn)
				ucv_stringbuf_printf(buf, "In %s(), ", ucv_string_get(fn));
			else if (path)
				ucv_stringbuf_printf(buf, "In %s, ", path);
			else
				ucv_stringbuf_append(buf, "In ");

			ucv_stringbuf_printf(buf, "line %" PRId64 ", byte %" PRId64 ":\n",
				ucv_int64_get(ucv_object_get(e, "line", NULL)),
				ucv_int64_get(ucv_object_get(e, "byte", NULL)));
		}
		else {
			line = ucv_object_get(e, "line", NULL);
			byte = ucv_object_get(e, "byte", NULL);

			ucv_stringbuf_printf(buf, "  called from %s%s (%s",
				fn ? "function " : "anonymous function",
				fn ? ucv_string_get(fn) : "",
				file ? ucv_string_get(file) : "");

			if (line && byte)
				ucv_stringbuf_printf(buf, ":%" PRId64 ":%" PRId64 ")\n",
					ucv_int64_get(line),
					ucv_int64_get(byte));
			else
				ucv_stringbuf_append(buf, "[C])\n");
		}
	}

	return uc_source_context_format(buf, src, off, false);
}

void
uc_error_message_indent(char **msg) {
	uc_stringbuf_t *buf = xprintbuf_new();
	char *s, *p, *nl;
	size_t len;

	if (!msg || !*msg)
		return;

	s = *msg;
	len = strlen(s);

	while (len > 0 && s[len-1] == '\n')
		s[--len] = 0;

	for (p = s, nl = strchr(p, '\n'); p != NULL;
	     p = nl ? nl + 1 : NULL, nl = p ? strchr(p, '\n') : NULL)
	{
		if (!nl)
			ucv_stringbuf_printf(buf, "  | %s", p);
		else if (nl != p)
			ucv_stringbuf_printf(buf, "  | %.*s\n", (int)(nl - p), p);
		else
			ucv_stringbuf_append(buf, "  |\n");
	}

	ucv_stringbuf_append(buf, "\n");

	*msg = buf->buf;

	free(buf);
	free(s);
}

static char *uc_cast_string(uc_vm_t *vm, uc_value_t **v, bool *freeable) {
	if (ucv_type(*v) == UC_STRING) {
		*freeable = false;

		return _ucv_string_get(v);
	}

	*freeable = true;

	return ucv_to_string(vm, *v);
}

static void
uc_vm_ctx_push(uc_vm_t *vm)
{
	uc_value_t *ctx = NULL;

	if (vm->callframes.count >= 2)
		ctx = vm->callframes.entries[vm->callframes.count - 2].ctx;

	uc_vm_stack_push(vm, ucv_get(ctx));
}

static uc_value_t *
uc_print_common(uc_vm_t *vm, size_t nargs, FILE *fh)
{
	uc_value_t *item;
	size_t reslen = 0;
	size_t len = 0;
	size_t arridx;
	char *p;

	for (arridx = 0; arridx < nargs; arridx++) {
		item = uc_fn_arg(arridx);

		if (ucv_type(item) == UC_STRING) {
			len = ucv_string_length(item);
			reslen += fwrite(ucv_string_get(item), 1, len, fh);
		}
		else if (item != NULL) {
			p = ucv_to_string(vm, item);
			len = strlen(p);
			reslen += fwrite(p, 1, len, fh);
			free(p);
		}
	}

	return ucv_int64_new(reslen);
}


/**
 * Print any of the given values to stdout.
 *
 * The `print()` function writes a string representation of each given argument
 * to stdout and returns the amount of bytes written.
 *
 * String values are printed as-is, integer and double values are printed in
 * decimal notation, boolean values are printed as `true` or `false` while
 * arrays and objects are converted to their JSON representation before being
 * written to the standard output. The `null` value is represented by an empty
 * string so `print(null)` would print nothing. Resource values are printed in
 * the form `<type address>`, e.g. `<fs.file 0x7f60f0981760>`.
 *
 * If resource, array or object values contain a `tostring()` function in their
 * prototypes, then this function is invoked to obtain an alternative string
 * representation of the value.
 *
 * Examples:
 *
 * ```javascript
 * print(1 != 2);                       // Will print 'true'
 * print(0xff);                         // Will print '255'
 * print(2e3);                          // Will print '2000'
 * print(null);                         // Will print nothing
 * print({ hello: true, world: 123 });  // Will print '{ "hello": true, "world": 123 }'
 * print([1,2,3]);                      // Will print '[ 1, 2, 3 ]'
 *
 * print(proto({ foo: "bar" },          // Will print 'MyObj'
 *   { tostring: () => "MyObj" }));     // instead of '{ "foo": "bar" }'
 *
 * ```
 *
 * Returns the amount of bytes printed.
 *
 * @function module:core#print
 *
 * @param {...*} values
 * Arbitrary values to print
 *
 * @returns {number}
 */
static uc_value_t *
uc_print(uc_vm_t *vm, size_t nargs)
{
	return uc_print_common(vm, nargs, vm->output);
}

/**
 * Determine the length of the given object, array or string.
 *
 * Returns the length of the given value.
 *
 *  - For strings, the length is the amount of bytes within the string
 *  - For arrays, the length is the amount of array elements
 *  - For objects, the length is defined as the amount of keys
 *
 * Returns `null` if the given argument is not an object, array or string.
 *
 * @function module:core#length
 *
 * @param {Object|Array|string} x - The input object, array, or string.
 *
 * @returns {?number} - The length of the input.
 *
 * @example
 * length("test")                             // 4
 * length([true, false, null, 123, "test"])   // 5
 * length({foo: true, bar: 123, baz: "test"}) // 3
 * length({})                                 // 0
 * length(true)                               // null
 * length(10.0)                               // null
 */
static uc_value_t *
uc_length(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *arg = uc_fn_arg(0);

	switch (ucv_type(arg)) {
	case UC_OBJECT:
		return ucv_int64_new(ucv_object_length(arg));

	case UC_ARRAY:
		return ucv_int64_new(ucv_array_length(arg));

	case UC_STRING:
		return ucv_int64_new(ucv_string_length(arg));

	default:
		return NULL;
	}
}

static int
uc_uniq_ucv_equal(const void *k1, const void *k2);

static uc_value_t *
uc_index(uc_vm_t *vm, size_t nargs, bool right)
{
	uc_value_t *stack = uc_fn_arg(0);
	uc_value_t *needle = uc_fn_arg(1);
	const char *sstr, *nstr, *p;
	size_t arridx, slen, nlen;
	ssize_t ret = -1;

	switch (ucv_type(stack)) {
	case UC_ARRAY:
		if (right) {
			for (arridx = ucv_array_length(stack); arridx > 0; arridx--) {
				if (uc_uniq_ucv_equal(ucv_array_get(stack, arridx - 1), needle)) {
					ret = (ssize_t)(arridx - 1);
					break;
				}
			}
		}
		else {
			for (arridx = 0, slen = ucv_array_length(stack); arridx < slen; arridx++) {
				if (uc_uniq_ucv_equal(ucv_array_get(stack, arridx), needle)) {
					ret = (ssize_t)arridx;
					break;
				}
			}
		}

		return ucv_int64_new(ret);

	case UC_STRING:
		if (ucv_type(needle) == UC_STRING) {
			sstr = ucv_string_get(stack);
			slen = ucv_string_length(stack);
			nstr = ucv_string_get(needle);
			nlen = ucv_string_length(needle);

			if (slen == nlen) {
				if (memcmp(sstr, nstr, nlen) == 0)
					ret = 0;
			}
			else if (slen > nlen) {
				if (right) {
					p = sstr + slen - nlen;

					do {
						if (memcmp(p, nstr, nlen) == 0) {
							ret = (ssize_t)(p - sstr);
							break;
						}
					}
					while (p-- != sstr);
				}
				else if (nlen > 0) {
					p = (const char *)memmem(sstr, slen, nstr, nlen);

					if (p)
						ret = (ssize_t)(p - sstr);
				}
				else {
					ret = 0;
				}
			}
		}

		return ucv_int64_new(ret);

	default:
		return NULL;
	}
}

/**
 * Finds the given value passed as the second argument within the array or
 * string specified in the first argument.
 *
 * Returns the first matching array index or first matching string offset or
 * `-1` if the value was not found.
 *
 * Returns `null` if the first argument was neither an array nor a string.
 *
 * @function module:core#index
 *
 * @param {Array|string} arr_or_str
 * The array or string to search for the value.
 *
 * @param {*} needle
 * The value to find within the array or string.
 *
 * @returns {?number}
 *
 * @example
 * index("Hello hello hello", "ll")          // 2
 * index([ 1, 2, 3, 1, 2, 3, 1, 2, 3 ], 2)   // 1
 * index("foo", "bar")                       // -1
 * index(["Red", "Blue", "Green"], "Brown")  // -1
 * index(123, 2)                             // null
 */
static uc_value_t *
uc_lindex(uc_vm_t *vm, size_t nargs)
{
	return uc_index(vm, nargs, false);
}

/**
 * Finds the given value passed as the second argument within the array or
 * string specified in the first argument.
 *
 * Returns the last matching array index or last matching string offset or
 * `-1` if the value was not found.
 *
 * Returns `null` if the first argument was neither an array nor a string.
 *
 * @function module:core#rindex
 *
 * @param {Array|string} arr_or_str
 * The array or string to search for the value.
 *
 * @param {*} needle
 * The value to find within the array or string.
 *
 * @returns {?number}
 *
 * @example
 * rindex("Hello hello hello", "ll")          // 14
 * rindex([ 1, 2, 3, 1, 2, 3, 1, 2, 3 ], 2)   //  7
 * rindex("foo", "bar")                       // -1
 * rindex(["Red", "Blue", "Green"], "Brown")  // -1
 * rindex(123, 2)                             // null
 */
static uc_value_t *
uc_rindex(uc_vm_t *vm, size_t nargs)
{
	return uc_index(vm, nargs, true);
}

static bool
assert_mutable(uc_vm_t *vm, uc_value_t *val)
{
	if (ucv_is_constant(val)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
		                      "%s value is immutable",
		                      ucv_typename(val));

		return false;
	}

	return true;
}

static bool
assert_mutable_array(uc_vm_t *vm, uc_value_t *val)
{
	if (ucv_type(val) != UC_ARRAY)
		return false;

	return assert_mutable(vm, val);
}

/**
 * Pushes the given argument(s) to the given array.
 *
 * Returns the last pushed value.
 *
 * @function module:core#push
 *
 * @param {Array} arr
 * The array to push values to.
 *
 * @param {...*} [values]
 * The values to push.
 *
 * @returns {*}
 *
 * @example
 * let x = [ 1, 2, 3 ];
 * push(x, 4, 5, 6);    // 6
 * print(x, "\n");      // [ 1, 2, 3, 4, 5, 6 ]
 */
static uc_value_t *
uc_push(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *arr = uc_fn_arg(0);
	uc_value_t *item = NULL;
	size_t arridx;

	if (!assert_mutable_array(vm, arr))
		return NULL;

	for (arridx = 1; arridx < nargs; arridx++) {
		item = uc_fn_arg(arridx);
		ucv_array_push(arr, ucv_get(item));
	}

	return ucv_get(item);
}

/**
 * Pops the last item from the given array and returns it.
 *
 * Returns `null` if the array was empty or if a non-array argument was passed.
 *
 * @function module:core#pop
 *
 * @param {Array} arr
 * The input array.
 *
 * @returns {*}
 *
 * @example
 * let x = [ 1, 2, 3 ];
 * pop(x);          // 3
 * print(x, "\n");  // [ 1, 2 ]
 */
static uc_value_t *
uc_pop(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *arr = uc_fn_arg(0);

	if (!assert_mutable_array(vm, arr))
		return NULL;

	return ucv_array_pop(arr);
}

/**
 * Pops the first item from the given array and returns it.
 *
 * Returns `null` if the array was empty or if a non-array argument was passed.
 *
 * @function module:core#shift
 *
 * @param {Array} arr
 * The array from which to pop the first item.
 *
 * @returns {*}
 *
 * @example
 * let x = [ 1, 2, 3 ];
 * shift(x);        // 1
 * print(x, "\n");  // [ 2, 3 ]
 */
static uc_value_t *
uc_shift(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *arr = uc_fn_arg(0);

	if (!assert_mutable_array(vm, arr))
		return NULL;

	return ucv_array_shift(arr);
}

/**
 * Add the given values to the beginning of the array passed via first argument.
 *
 * Returns the last value added to the array.
 *
 * @function module:core#unshift
 *
 * @param {Array} arr
 * The array to which the values will be added.
 *
 * @param {...*}
 * Values to add.
 *
 * @returns {*}
 *
 * @example
 * let x = [ 3, 4, 5 ];
 * unshift(x, 1, 2);  // 2
 * print(x, "\n");    // [ 1, 2, 3, 4, 5 ]
 */
static uc_value_t *
uc_unshift(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *arr = uc_fn_arg(0);
	uc_value_t *item;
	size_t i;

	if (!assert_mutable_array(vm, arr))
		return NULL;

	for (i = 1; i < nargs; i++) {
		item = uc_fn_arg(nargs - i);
		ucv_array_unshift(arr, ucv_get(item));
	}

	return (nargs > 1) ? ucv_get(uc_fn_arg(nargs - 1)) : NULL;
}

/**
 * Converts each given numeric value to a byte and return the resulting string.
 * Invalid numeric values or values < 0 result in `\0` bytes, values larger than
 * 255 are truncated to 255.
 *
 * Returns a new strings consisting of the given byte values.
 *
 * @function module:core#chr
 *
 * @param {...number} n1
 * The numeric values.
 *
 * @returns {string}
 *
 * @example
 * chr(65, 98, 99);  // "Abc"
 * chr(-1, 300);     // string consisting of an `0x0` and a `0xff` byte
 */
static uc_value_t *
uc_chr(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *rv = NULL;
	size_t idx;
	int64_t n;
	char *str;

	if (!nargs)
		return ucv_string_new_length("", 0);

	str = xalloc(nargs);

	for (idx = 0; idx < nargs; idx++) {
		n = ucv_to_integer(uc_fn_arg(idx));

		if (n < 0)
			n = 0;
		else if (n > 255)
			n = 255;

		str[idx] = (char)n;
	}

	rv = ucv_string_new_length(str, nargs);
	free(str);

	return rv;
}

/**
 * Raise an exception with the given message and abort execution.
 *
 * @function module:core#die
 *
 * @param {string} msg
 * The error message.
 *
 * @throws {Error}
 * The error with the given message.
 *
 * @example
 * die(msg);
 */
static uc_value_t *
uc_die(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *msg = uc_fn_arg(0);
	bool freeable = false;
	char *s;

	s = msg ? uc_cast_string(vm, &msg, &freeable) : "Died";

	uc_vm_raise_exception(vm, EXCEPTION_USER, "%s", s);

	if (freeable)
		free(s);

	return NULL;
}

/**
 * Check whether the given key exists within the given object value.
 *
 * Returns `true` if the given key is present within the object passed as the
 * first argument, otherwise `false`.
 *
 * @function module:core#exists
 *
 * @param {Object} obj
 * The input object.
 *
 * @param {string} key
 * The key to check for existence.
 *
 * @returns {boolean}
 *
 * @example
 * let x = { foo: true, bar: false, qrx: null };
 * exists(x, 'foo');  // true
 * exists(x, 'qrx');  // true
 * exists(x, 'baz');  // false
 */
static uc_value_t *
uc_exists(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *obj = uc_fn_arg(0);
	uc_value_t *key = uc_fn_arg(1);
	bool found, freeable;
	char *k;

	if (ucv_type(obj) != UC_OBJECT)
		return ucv_boolean_new(false);

	k = uc_cast_string(vm, &key, &freeable);

	ucv_object_get(obj, k, &found);

	if (freeable)
		free(k);

	return ucv_boolean_new(found);
}

/**
 * Terminate the interpreter with the given exit code.
 *
 * This function does not return.
 *
 * @function module:core#exit
 *
 * @param {number} n
 * The exit code.
 *
 * @example
 * exit();
 * exit(5);
 */
static uc_value_t *
uc_exit(uc_vm_t *vm, size_t nargs)
{
	int64_t n = ucv_to_integer(uc_fn_arg(0));

	vm->arg.s32 = (int32_t)n;
	uc_vm_raise_exception(vm, EXCEPTION_EXIT, "Terminated");

	return NULL;
}

/**
 * Query an environment variable or then entire environment.
 *
 * Returns the value of the given environment variable, or - if omitted - a
 * dictionary containing all environment variables.
 *
 * @function module:core#getenv
 *
 * @param {string} [name]
 * The name of the environment variable.
 *
 * @returns {string|Object<string, string>}
 */
static uc_value_t *
uc_getenv(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *key = uc_fn_arg(0), *rv = NULL;
	extern char **environ;
	char **env = environ;
	char *k, *v;

	if (!key) {
		rv = ucv_object_new(vm);

		while (*env) {
			v = strchr(*env, '=');

			if (v) {
				xasprintf(&k, "%.*s", (int)(v - *env), *env);
				ucv_object_add(rv, k, ucv_string_new(v + 1));
				free(k);
			}

			env++;
		}
	}
	else if (ucv_type(key) == UC_STRING) {
		k = ucv_string_get(key);
		v = getenv(k);

		if (v)
			rv = ucv_string_new(v);
	}

	return rv;
}

/**
 * Filter the array passed as the first argument by invoking the function
 * specified in the second argument for each array item.
 *
 * If the invoked function returns a truthy result, the item is retained,
 * otherwise, it is dropped. The filter function is invoked with three
 * arguments:
 *
 * 1. The array value
 * 2. The current index
 * 3. The array being filtered
 *
 * (Note that the `map` function behaves similarly to `filter` with respect
 * to its `fn` parameters.)
 *
 * Returns a new array containing only retained items, in the same order as
 * the input array.
 *
 * @function module:core#filter
 *
 * @param {Array} arr
 * The input array.
 *
 * @param {Function} fn
 * The filter function.
 *
 * @returns {Array}
 *
 * @example
 * // filter out any empty string:
 * a = filter(["foo", "", "bar", "", "baz"], length)
 * // a = ["foo", "bar", "baz"]
 *
 * // filter out any non-number type:
 * a = filter(["foo", 1, true, null, 2.2], function(v) {
 *     return (type(v) == "int" || type(v) == "double");
 * });
 * // a = [1, 2.2]
 */
static uc_value_t *
uc_filter(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *obj = uc_fn_arg(0);
	uc_value_t *func = uc_fn_arg(1);
	uc_value_t *rv, *arr;
	size_t arridx, arrlen;

	if (ucv_type(obj) != UC_ARRAY)
		return NULL;

	arr = ucv_array_new(vm);

	for (arrlen = ucv_array_length(obj), arridx = 0; arridx < arrlen; arridx++) {
		uc_vm_ctx_push(vm);
		uc_vm_stack_push(vm, ucv_get(func));
		uc_vm_stack_push(vm, ucv_get(ucv_array_get(obj, arridx)));
		uc_vm_stack_push(vm, ucv_int64_new(arridx));
		uc_vm_stack_push(vm, ucv_get(obj));

		if (uc_vm_call(vm, true, 3)) {
			ucv_put(arr);

			return NULL;
		}

		rv = uc_vm_stack_pop(vm);

		if (ucv_is_truish(rv))
			ucv_array_push(arr, ucv_get(ucv_array_get(obj, arridx)));

		ucv_put(rv);
	}

	return arr;
}

/**
 * Converts the given hexadecimal string into a number.
 *
 * Returns the resulting integer value or `NaN` if the input value cannot be
 * interpreted as hexadecimal number.
 *
 * @function module:core#hex
 *
 * @param {*} x
 * The hexadecimal string to be converted.
 *
 * @returns {number}
 */
static uc_value_t *
uc_hex(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *val = uc_fn_arg(0);
	char *e, *v;
	int64_t n;

	v = ucv_string_get(val);

	if (!v || !isxdigit(*v))
		return ucv_double_new(NAN);

	n = strtoll(v, &e, 16);

	if (e == v || *e)
		return ucv_double_new(NAN);

	return ucv_int64_new(n);
}

/**
 * Converts the given value to an integer, using an optional base.
 *
 * Returns `NaN` if the value is not convertible.
 *
 * @function module:core#int
 *
 * @param {*} x
 * The value to be converted to an integer.
 *
 * @param {int} [base]
 * The base into which the value is to be converted, the default is 10.
 * Note that the base parameter is ignored if the `x` value is already numeric.
 *
 * @returns {number}
 *
 * @example
 * int("123")         // Returns 123
 * int("123", 10)     // 123
 * int("10 or more")  // 10
 * int("12.3")        // 12
 * int("123", 7)      // 66
 * int("abc", 16)     // 2748
 * int("xyz", 36)     // 44027
 * int(10.10, "2")    // 10, the invalid base is ignored
 * int("xyz", 16)     // NaN, bad value
 * int("1010", "2")   // NaN, bad base
 */
static uc_value_t *
uc_int(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *val = uc_fn_arg(0);
	uc_value_t *base = uc_fn_arg(1);
	char *e, *v;
	int64_t n;

	if (ucv_type(val) == UC_STRING) {
		errno = 0;
		v = ucv_string_get(val);
		n = strtoll(v, &e, base ? ucv_int64_get(base) : 10);

		if (e == v)
			return ucv_double_new(NAN);
	}
	else {
		n = ucv_to_integer(val);
	}

	if (errno == EINVAL || errno == ERANGE)
		return ucv_double_new(NAN);

	return ucv_int64_new(n);
}

/**
 * Joins the array passed as the second argument into a string, using the
 * separator passed in the first argument as glue.
 *
 * Returns `null` if the second argument is not an array.
 *
 * @function module:core#join
 *
 * @param {string} sep
 * The separator to be used in joining the array elements.
 *
 * @param {Array} arr
 * The array to be joined into a string.
 *
 * @returns {?string}
 */
static uc_value_t *
uc_join(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *sep = uc_fn_arg(0);
	uc_value_t *arr = uc_fn_arg(1);
	size_t arrlen, arridx;
	uc_stringbuf_t *buf;

	if (ucv_type(arr) != UC_ARRAY)
		return NULL;

	buf = ucv_stringbuf_new();

	for (arrlen = ucv_array_length(arr), arridx = 0; arridx < arrlen; arridx++) {
		if (arridx > 0)
			ucv_to_stringbuf(vm, buf, sep, false);

		ucv_to_stringbuf(vm, buf, ucv_array_get(arr, arridx), false);
	}

	return ucv_stringbuf_finish(buf);
}

/**
 * Enumerates all object key names.
 *
 * Returns an array of all key names present in the passed object.
 * Returns `null` if the given argument is not an object.
 *
 * @function module:core#keys
 *
 * @param {object} obj
 * The object from which to retrieve the key names.
 *
 * @returns {?Array}
 */
static uc_value_t *
uc_keys(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *obj = uc_fn_arg(0);
	uc_value_t *arr = NULL;

	if (ucv_type(obj) != UC_OBJECT)
		return NULL;

	arr = ucv_array_new(vm);

	ucv_object_foreach(obj, key, val) {
		(void)val;
		ucv_array_push(arr, ucv_string_new(key));
	}

	return arr;
}

/**
 * Convert the given string to lowercase and return the resulting string.
 *
 * Returns `null` if the given argument could not be converted to a string.
 *
 * @function module:core#lc
 *
 * @param {string} s
 * The input string.
 *
 * @returns {?string}
 * The lowercase string.
 *
 * @example
 * lc("HeLLo WoRLd!");  // "hello world!"
 */
static uc_value_t *
uc_lc(uc_vm_t *vm, size_t nargs)
{
	char *str = ucv_to_string(vm, uc_fn_arg(0));
	uc_value_t *rv = NULL;
	char *p;

	if (!str)
		return NULL;

	for (p = str; *p; p++)
		if (*p >= 'A' && *p <= 'Z')
			*p |= 32;

	rv = ucv_string_new(str);

	free(str);

	return rv;
}

/**
 * Transform the array passed as the first argument by invoking the function
 * specified in the second argument for each array item.
 *
 * The mapping function is invoked with three arguments (see examples, below,
 * for some possibly counterintuitive usage):
 *
 * 1. The array value
 * 2. The current index
 * 3. The array being filtered
 *
 * (Note that the `filter` function behaves similarly to `map` with respect
 * to its `fn` parameters.)
 *
 * Returns a new array of the same length as the input array containing the
 * transformed values.
 *
 * @function module:core#map
 *
 * @param {Array} arr
 * The input array.
 *
 * @param {Function} fn
 * The mapping function.
 *
 * @returns {Array}
 *
 * @example
 * // turn into an array of string lengths:
 * a = map(["Apple", "Banana", "Bean"], length);
 * // a = [5, 6, 4]
 *
 * // map to type names:
 * a = map(["foo", 1, true, null, 2.2], type);
 * // a = ["string", "int", "bool", null, "double"]
 *
 * // attempt to naively use built-in 'int' to map an array:
 * a = map(["x", "2", "11", "7"], int)
 * // a = [NaN, NaN, 3, NaN]
 * //
 * // This is a direct result of 'int' being provided the second, index parameter
 * // for its base value in the conversion.
 * //
 * // The resulting calls to 'int' are as follows:
 * //  int("x",  0, [...]) - convert "x"  to base 0, 'int' ignores the third value
 * //  int("2",  1, [...]) - convert "2"  to base 1, digit out of range, so NaN
 * //  int("11", 2, [...]) - convert "11" to base 2, produced unexpected 3
 * //  int("7",  3, [...]) - convert "7"  to base 3, digit out of range, NaN again
 *
 * // remedy this by using an arrow function to ensure the proper base value
 * // (in this case, the default of 10) is passed to 'int':
 * a = map(["x", "2", "1", "7"], (x) => int(x))
 * // a = [NaN, 2, 1, 7]
 *
 * // convert base-2 values:
 * a = map(["22", "1010", "0001", "0101"], (x) => int(x, 2))
 * // a = [NaN, 10, 1, 5]
 */
static uc_value_t *
uc_map(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *obj = uc_fn_arg(0);
	uc_value_t *func = uc_fn_arg(1);
	uc_value_t *arr, *rv;
	size_t arridx, arrlen;

	if (ucv_type(obj) != UC_ARRAY)
		return NULL;

	arr = ucv_array_new(vm);

	for (arrlen = ucv_array_length(obj), arridx = 0; arridx < arrlen; arridx++) {
		uc_vm_ctx_push(vm);
		uc_vm_stack_push(vm, ucv_get(func));
		uc_vm_stack_push(vm, ucv_get(ucv_array_get(obj, arridx)));
		uc_vm_stack_push(vm, ucv_int64_new(arridx));
		uc_vm_stack_push(vm, ucv_get(obj));

		if (uc_vm_call(vm, true, 3)) {
			ucv_put(arr);

			return NULL;
		}

		rv = uc_vm_stack_pop(vm);

		ucv_array_push(arr, rv);
	}

	return arr;
}

/**
 * Without further arguments, this function returns the byte value of the first
 * character in the given string.
 *
 * If an offset argument is supplied, the byte value of the character at this
 * position is returned. If an invalid index is supplied, the function will
 * return `null`. Negative index entries are counted towards the end of the
 * string, e.g. `-2` will return the value of the second last character.
 *
 * Returns the byte value of the character.
 * Returns `null` if the offset is invalid or if the input is not a string.
 *
 * @function module:core#ord
 *
 * @param {string} s
 * The input string.
 *
 * @param {number} [offset]
 * The offset of the character.
 *
 * @returns {?number}
 *
 * @example
 * ord("Abc");         // 65
 * ord("Abc", 0);      // 65
 * ord("Abc", 1);      // 98
 * ord("Abc", 2);      // 99
 * ord("Abc", 10);     // null
 * ord("Abc", -10);    // null
 * ord("Abc", "nan");  // null
 */
static uc_value_t *
uc_ord(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *obj = uc_fn_arg(0);
	const char *str;
	int64_t n = 0;
	size_t len;

	if (ucv_type(obj) != UC_STRING)
		return NULL;

	str = ucv_string_get(obj);
	len = ucv_string_length(obj);

	if (nargs > 1) {
		n = ucv_int64_get(uc_fn_arg(1));

		if (errno == EINVAL)
			return NULL;

		if (n < 0)
			n += len;
	}

	if (n < 0 || (uint64_t)n >= len)
		return NULL;

	return ucv_int64_new((uint8_t)str[n]);
}

/**
 * Query the type of the given value.
 *
 * Returns the type of the given value as a string which might be one of
 * `"function"`, `"object"`, `"array"`, `"double"`, `"int"`, or `"bool"`.
 *
 * Returns `null` when no value or `null` is passed.
 *
 * @function module:core#type
 *
 * @param {*} x
 * The value to determine the type of.
 *
 * @returns {?string}
 */
static uc_value_t *
uc_type(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *v = uc_fn_arg(0);
	uc_type_t t = ucv_type(v);

	switch (t) {
	case UC_CFUNCTION:
	case UC_CLOSURE:
		return ucv_string_new("function");

	case UC_INTEGER:
		return ucv_string_new("int");

	case UC_BOOLEAN:
		return ucv_string_new("bool");

	case UC_NULL:
		return NULL;

	default:
		return ucv_string_new(ucv_typename(v));
	}
}

/**
 * Reverse the order of the given input array or string.
 *
 * If an array is passed, returns the array in reverse order.
 * If a string is passed, returns the string with the sequence of the characters
 * reversed.
 *
 * Returns the reversed array or string.
 * Returns `null` if neither an array nor a string were passed.
 *
 * @function module:core#reverse
 *
 * @param {Array|string} arr_or_str
 * The input array or string.
 *
 * @returns {?(Array|string)}
 *
 * @example
 * reverse([1, 2, 3]);   // [ 3, 2, 1 ]
 * reverse("Abc");       // "cbA"
 */
static uc_value_t *
uc_reverse(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *obj = uc_fn_arg(0);
	uc_value_t *rv = NULL;
	size_t len, arridx;
	const char *str;
	char *dup, *p;

	if (ucv_type(obj) == UC_ARRAY) {
		if (!assert_mutable_array(vm, obj))
			return NULL;

		rv = ucv_array_new(vm);

		for (arridx = ucv_array_length(obj); arridx > 0; arridx--)
			ucv_array_push(rv, ucv_get(ucv_array_get(obj, arridx - 1)));
	}
	else if (ucv_type(obj) == UC_STRING) {
		len = ucv_string_length(obj);
		str = ucv_string_get(obj);
		p = dup = xalloc(len + 1);

		while (len > 0)
			*p++ = str[--len];

		rv = ucv_string_new(dup);

		free(dup);
	}

	return rv;
}


typedef struct {
	uc_vm_t *vm;
	bool ex;
	uc_value_t *fn;
} sort_ctx_t;

static int
default_cmp(uc_value_t *v1, uc_value_t *v2, uc_vm_t *vm)
{
	char *s1, *s2;
	bool f1, f2;
	int res;

	/* when both operands are numeric then compare numerically */
	if ((ucv_type(v1) == UC_INTEGER || ucv_type(v1) == UC_DOUBLE) &&
	    (ucv_type(v2) == UC_INTEGER || ucv_type(v2) == UC_DOUBLE)) {
		ucv_compare(0, v1, v2, &res);

		return res;
	}

	/* otherwise convert both operands to strings and compare lexically */
	s1 = uc_cast_string(vm, &v1, &f1);
	s2 = uc_cast_string(vm, &v2, &f2);

	res = strcmp(s1, s2);

	if (f1) free(s1);
	if (f2) free(s2);

	return res;
}

static int
array_sort_fn(uc_value_t *v1, uc_value_t *v2, void *ud)
{
	uc_value_t *rv, *null = ucv_int64_new(0);
	sort_ctx_t *ctx = ud;
	int res;

	if (!ctx->fn)
		return default_cmp(v1, v2, ctx->vm);

	if (ctx->ex)
		return 0;

	uc_vm_ctx_push(ctx->vm);
	uc_vm_stack_push(ctx->vm, ucv_get(ctx->fn));
	uc_vm_stack_push(ctx->vm, ucv_get(v1));
	uc_vm_stack_push(ctx->vm, ucv_get(v2));

	if (uc_vm_call(ctx->vm, true, 2)) {
		ctx->ex = true;

		return 0;
	}

	rv = uc_vm_stack_pop(ctx->vm);

	ucv_compare(0, rv, null, &res);

	ucv_put(null);
	ucv_put(rv);

	return res;
}

static int
object_sort_fn(const char *k1, uc_value_t *v1, const char *k2, uc_value_t *v2,
               void *ud)
{
	uc_value_t *rv, *null = ucv_int64_new(0);
	sort_ctx_t *ctx = ud;
	int res;

	if (!ctx->fn)
		return strcmp(k1, k2);

	if (ctx->ex)
		return 0;

	uc_vm_ctx_push(ctx->vm);
	uc_vm_stack_push(ctx->vm, ucv_get(ctx->fn));
	uc_vm_stack_push(ctx->vm, ucv_string_new(k1));
	uc_vm_stack_push(ctx->vm, ucv_string_new(k2));
	uc_vm_stack_push(ctx->vm, ucv_get(v1));
	uc_vm_stack_push(ctx->vm, ucv_get(v2));

	if (uc_vm_call(ctx->vm, true, 4)) {
		ctx->ex = true;

		return 0;
	}

	rv = uc_vm_stack_pop(ctx->vm);

	ucv_compare(0, rv, null, &res);

	ucv_put(null);
	ucv_put(rv);

	return res;
}

/**
 * Sort the given array according to the given sort function.
 * If no sort function is provided, a default ascending sort order is applied.
 *
 * The input array is sorted in-place, no copy is made.
 *
 * The custom sort function is repeatedly called until the entire array is
 * sorted. It will receive two values as arguments and should return a value
 * lower than, larger than or equal to zero depending on whether the first
 * argument is smaller, larger or equal to the second argument respectively.
 *
 * Returns the sorted input array.
 *
 * @function module:core#sort
 *
 * @param {Array} arr
 * The input array to be sorted.
 *
 * @param {Function} [fn]
 * The sort function.
 *
 * @returns {Array}
 *
 * @example
 * sort([8, 1, 5, 9]) // [1, 5, 8, 9]
 * sort(["Bean", "Orange", "Apple"], function(a, b) {
 *    return length(a) - length(b);
 * }) // ["Bean", "Apple", "Orange"]
 */
static uc_value_t *
uc_sort(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *val = uc_fn_arg(0);
	uc_value_t *fn = uc_fn_arg(1);
	sort_ctx_t ctx = {
		.vm = vm,
		.fn = fn,
		.ex = false
	};

	if (!assert_mutable(vm, val))
		return NULL;

	switch (ucv_type(val)) {
	case UC_ARRAY:
		ucv_array_sort_r(val, array_sort_fn, &ctx);
		break;

	case UC_OBJECT:
		ucv_object_sort_r(val, object_sort_fn, &ctx);
		break;

	default:
		return NULL;
	}

	return ctx.ex ? NULL : ucv_get(val);
}

/**
 * Removes the elements designated by `off` and `len` from the given array,
 * and replaces them with the additional arguments passed, if any.
 *
 * The array grows or shrinks as necessary.
 *
 * Returns the modified input array.
 *
 * @function module:core#splice
 *
 * @param {Array} arr
 * The input array to be modified.
 *
 * @param {number} off
 * The index to start removing elements.
 *
 * @param {number} [len]
 * The number of elements to remove.
 *
 * @param {...*} [elements]
 * The elements to insert.
 *
 * @returns {*}
 *
 * @example
 * let x = [ 1, 2, 3, 4 ];
 * splice(x, 1, 2, "a", "b", "c");  // [ 1, "a", "b", "c", 4 ]
 * print(x, "\n");                  // [ 1, "a", "b", "c", 4 ]
 */
static uc_value_t *
uc_splice(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *arr = uc_fn_arg(0);
	int64_t ofs = ucv_to_integer(uc_fn_arg(1));
	int64_t remlen = ucv_to_integer(uc_fn_arg(2));
	size_t arrlen, addlen, idx;

	if (!assert_mutable_array(vm, arr))
		return NULL;

	arrlen = ucv_array_length(arr);
	addlen = nargs;

	if (addlen == 1) {
		ofs = 0;
		addlen = 0;
		remlen = arrlen;
	}
	else if (addlen == 2) {
		if (ofs < 0) {
			ofs = arrlen + ofs;

			if (ofs < 0)
				ofs = 0;
		}
		else if ((uint64_t)ofs > arrlen) {
			ofs = arrlen;
		}

		addlen = 0;
		remlen = arrlen - ofs;
	}
	else {
		if (ofs < 0) {
			ofs = arrlen + ofs;

			if (ofs < 0)
				ofs = 0;
		}
		else if ((uint64_t)ofs > arrlen) {
			ofs = arrlen;
		}

		if (remlen < 0) {
			remlen = arrlen - ofs + remlen;

			if (remlen < 0)
				remlen = 0;
		}
		else if ((uint64_t)remlen > arrlen - (uint64_t)ofs) {
			remlen = arrlen - ofs;
		}

		addlen -= 3;
	}

	if (addlen < (uint64_t)remlen) {
		ucv_array_delete(arr, ofs, remlen - addlen);
	}
	else if (addlen > (uint64_t)remlen) {
		for (idx = arrlen; idx > (uint64_t)ofs; idx--)
			ucv_array_set(arr, idx + addlen - remlen - 1,
				ucv_get(ucv_array_get(arr, idx - 1)));
	}

	for (idx = 0; idx < addlen; idx++)
		ucv_array_set(arr, ofs + idx,
			ucv_get(uc_fn_arg(3 + idx)));

	return ucv_get(arr);
}

/**
 * Performs a shallow copy of a portion of the source array, as specified by
 * the start and end offsets. The original array is not modified.
 *
 * Returns a new array containing the copied elements, if any.
 * Returns `null` if the given source argument is not an array value.
 *
 * @function module:core#slice
 *
 * @param {Array} arr
 * The source array to be copied.
 *
 * @param {number} [off]
 * The index of the first element to copy.
 *
 * @param {number} [end]
 * The index of the first element to exclude from the returned array.
 *
 * @returns {Array}
 *
 * @example
 * slice([1, 2, 3])          // [1, 2, 3]
 * slice([1, 2, 3], 1)       // [2, 3]
 * slice([1, 2, 3], -1)      // [3]
 * slice([1, 2, 3], -3, -1)  // [1, 2]
 * slice([1, 2, 3], 10)      // []
 * slice([1, 2, 3], 2, 1)    // []
 * slice("invalid", 1, 2)    // null
 */
static uc_value_t *
uc_slice(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *arr = uc_fn_arg(0);
	uc_value_t *sv = uc_fn_arg(1);
	uc_value_t *ev = uc_fn_arg(2);
	uc_value_t *res = NULL;
	int64_t off, end;
	size_t len;

	if (ucv_type(arr) != UC_ARRAY)
		return NULL;

	len = ucv_array_length(arr);
	off = sv ? ucv_to_integer(sv) : 0;
	end = ev ? ucv_to_integer(ev) : (int64_t)len;

	if (off < 0) {
		off = len + off;

		if (off < 0)
			off = 0;
	}
	else if ((uint64_t)off > len) {
		off = len;
	}

	if (end < 0) {
		end = len + end;

		if (end < 0)
			end = 0;
	}
	else if ((uint64_t)end > len) {
		end = len;
	}

	res = ucv_array_new(vm);

	while (off < end)
		ucv_array_push(res, ucv_get(ucv_array_get(arr, off++)));

	return res;
}

/**
 * Split the given string using the separator passed as the second argument
 * and return an array containing the resulting pieces.
 *
 * If a limit argument is supplied, the resulting array contains no more than
 * the given amount of entries, that means the string is split at most
 * `limit - 1` times total.
 *
 * The separator may either be a plain string or a regular expression.
 *
 * Returns a new array containing the resulting pieces.
 *
 * @function module:core#split
 *
 * @param {string} str
 * The input string to be split.
 *
 * @param {string|RegExp} sep
 * The separator.
 *
 * @param {number} [limit]
 * The limit on the number of splits.
 *
 * @returns {Array}
 *
 * @example
 * split("foo,bar,baz", ",")     // ["foo", "bar", "baz"]
 * split("foobar", "")           // ["f", "o", "o", "b", "a", "r"]
 * split("foo,bar,baz", /[ao]/)  // ["f", "", ",b", "r,b", "z"]
 * split("foo=bar=baz", "=", 2)  // ["foo", "bar=baz"]
 */
static uc_value_t *
uc_split(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *str = uc_fn_arg(0);
	uc_value_t *sep = uc_fn_arg(1);
	uc_value_t *lim = uc_fn_arg(2);
	uc_value_t *arr = NULL;
	const char *p, *sepstr, *splitstr;
	size_t seplen, splitlen, limit;
	int eflags = 0, res;
	regmatch_t pmatch;
	uc_regexp_t *re;

	if (!sep || ucv_type(str) != UC_STRING)
		return NULL;

	arr = ucv_array_new(vm);
	splitlen = ucv_string_length(str);
	p = splitstr = ucv_string_get(str);
	limit = lim ? ucv_uint64_get(lim) : SIZE_MAX;

	if (limit == 0)
		goto out;

	if (ucv_type(sep) == UC_REGEXP) {
		re = (uc_regexp_t *)sep;

		while (limit > 1) {
			res = regexec(&re->regexp, splitstr, 1, &pmatch, eflags);

			if (res == REG_NOMATCH)
				break;

			if (pmatch.rm_so != pmatch.rm_eo) {
				ucv_array_push(arr, ucv_string_new_length(splitstr, pmatch.rm_so));
				splitstr += pmatch.rm_eo;
			}
			else if (*splitstr) {
				ucv_array_push(arr, ucv_string_new_length(splitstr, 1));
				splitstr++;
			}
			else {
				goto out;
			}

			eflags |= REG_NOTBOL;
			limit--;
		}

		ucv_array_push(arr, ucv_string_new(splitstr));
	}
	else if (ucv_type(sep) == UC_STRING) {
		sepstr = ucv_string_get(sep);
		seplen = ucv_string_length(sep);

		if (splitlen == 0) {
			ucv_array_push(arr, ucv_string_new_length("", 0));
		}
		else if (seplen == 0) {
			while (limit > 1 && splitlen > 0) {
				ucv_array_push(arr, ucv_string_new_length(p, 1));

				limit--;
				splitlen--;
				p++;
			}

			if (splitlen > 0)
				ucv_array_push(arr, ucv_string_new_length(p, splitlen));
		}
		else {
			while (limit > 1 && splitlen >= seplen) {
				if (!memcmp(p, sepstr, seplen)) {
					ucv_array_push(arr, ucv_string_new_length(splitstr, p - splitstr));

					p = splitstr = p + seplen;
					splitlen -= seplen;
					limit--;
					continue;
				}

				splitlen--;
				p++;
			}

			ucv_array_push(arr, ucv_string_new_length(splitstr, p - splitstr + splitlen));
		}
	}
	else {
		ucv_put(arr);

		return NULL;
	}

out:
	return arr;
}

/**
 * Extracts a substring out of `str` and returns it. First character is at
 * offset zero.
 *
 *  - If `off` is negative, starts that far back from the end of the string.
 *  - If `len` is omitted, returns everything through the end of the string.
 *  - If `len` is negative, leaves that many characters off the string end.
 *
 * Returns the extracted substring.
 *
 * @function module:core#substr
 *
 * @param {string} str
 * The input string.
 *
 * @param {number} off
 * The starting offset.
 *
 * @param {number} [len]
 * The length of the substring.
 *
 * @returns {string}
 *
 * @example
 * s = "The black cat climbed the green tree";
 * substr(s, 4, 5);      // black
 * substr(s, 4, -11);    // black cat climbed the
 * substr(s, 14);        // climbed the green tree
 * substr(s, -4);        // tree
 * substr(s, -4, 2);     // tr
 */
static uc_value_t *
uc_substr(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *str = uc_fn_arg(0);
	int64_t ofs = ucv_to_integer(uc_fn_arg(1));
	int64_t sublen = ucv_to_integer(uc_fn_arg(2));
	const char *p;
	size_t len;

	if (ucv_type(str) != UC_STRING)
		return NULL;

	p = ucv_string_get(str);
	len = ucv_string_length(str);

	switch (nargs) {
	case 1:
		ofs = 0;
		sublen = len;

		break;

	case 2:
		if (ofs < 0) {
			ofs = len + ofs;

			if (ofs < 0)
				ofs = 0;
		}
		else if ((uint64_t)ofs > len) {
			ofs = len;
		}

		sublen = len - ofs;

		break;

	default:
		if (ofs < 0) {
			ofs = len + ofs;

			if (ofs < 0)
				ofs = 0;
		}
		else if ((uint64_t)ofs > len) {
			ofs = len;
		}

		if (sublen < 0) {
			sublen = len - ofs + sublen;

			if (sublen < 0)
				sublen = 0;
		}
		else if ((uint64_t)sublen > len - (uint64_t)ofs) {
			sublen = len - ofs;
		}

		break;
	}

	return ucv_string_new_length(p + ofs, sublen);
}

/**
 * Returns the current UNIX epoch.
 *
 * @function module:core#time
 *
 * @returns {number}
 *
 * @example
 * time();     // 1598043054
 */
static uc_value_t *
uc_time(uc_vm_t *vm, size_t nargs)
{
	time_t t = time(NULL);

	return ucv_int64_new((int64_t)t);
}

/**
 * Converts the given string to uppercase and returns the resulting string.
 *
 * Returns null if the given argument could not be converted to a string.
 *
 * @function module:core#uc
 *
 * @param {*} str
 * The string to be converted to uppercase.
 *
 * @returns {?string}
 *
 * @example
 * uc("hello");   // "HELLO"
 * uc(123);       // null
 */

static uc_value_t *
uc_uc(uc_vm_t *vm, size_t nargs)
{
	char *str = ucv_to_string(vm, uc_fn_arg(0));
	uc_value_t *rv = NULL;
	char *p;

	if (!str)
		return NULL;

	for (p = str; *p; p++)
		if (*p >= 'a' && *p <= 'z')
			*p &= ~32;

	rv = ucv_string_new(str);

	free(str);

	return rv;
}

/**
 * Converts each given numeric value to an UTF-8 multibyte sequence and returns
 * the resulting string.
 *
 * Invalid numeric values or values outside the range `0`..`0x10FFFF` are
 * represented by the unicode replacement character `0xFFFD`.
 *
 * Returns a new UTF-8 encoded string consisting of unicode characters
 * corresponding to the given numeric codepoints.
 *
 * @function module:core#uchr
 *
 * @param {...number}
 * Numeric values to convert.
 *
 * @returns {string}
 *
 * @example
 * uchr(0x2600, 0x26C6, 0x2601);  // "☀⛆☁"
 * uchr(-1, 0x20ffff, "foo");     // "���"
 */
static uc_value_t *
uc_uchr(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *rv = NULL;
	size_t idx, ulen;
	char *p, *str;
	int64_t n;
	int rem;

	for (idx = 0, ulen = 0; idx < nargs; idx++) {
		n = ucv_to_integer(uc_fn_arg(idx));

		if (errno == EINVAL || errno == ERANGE || n < 0 || n > 0x10FFFF)
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

	str = xalloc(ulen);

	for (idx = 0, p = str, rem = ulen; idx < nargs; idx++) {
		n = ucv_to_integer(uc_fn_arg(idx));

		if (errno == EINVAL || errno == ERANGE || n < 0 || n > 0x10FFFF)
			n = 0xFFFD;

		if (!utf8enc(&p, &rem, n))
			break;
	}

	rv = ucv_string_new_length(str, ulen);

	free(str);

	return rv;
}

/**
 * Returns an array containing all values of the given object.
 *
 * Returns null if no object was passed.
 *
 * @function module:core#values
 *
 * @param {*} obj
 * The object from which to extract values.
 *
 * @returns {?Array}
 *
 * @example
 * values({ foo: true, bar: false });   // [true, false]
 */
static uc_value_t *
uc_values(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *obj = uc_fn_arg(0);
	uc_value_t *arr;

	if (ucv_type(obj) != UC_OBJECT)
		return NULL;

	arr = ucv_array_new(vm);

	ucv_object_foreach(obj, key, val) {
		(void)key;
		ucv_array_push(arr, ucv_get(val));
	}

	return arr;
}

static uc_value_t *
uc_trim_common(uc_vm_t *vm, size_t nargs, bool start, bool end)
{
	uc_value_t *str = uc_fn_arg(0);
	uc_value_t *chr = uc_fn_arg(1);
	const char *p, *c;
	size_t len;

	if (ucv_type(str) != UC_STRING ||
		(chr != NULL && ucv_type(chr) != UC_STRING))
		return NULL;

	c = ucv_string_get(chr);
	c = c ? c : " \t\r\n";

	p = ucv_string_get(str);
	len = ucv_string_length(str);

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

	return ucv_string_new_length(p, len);
}

/**
 * Trim any of the specified characters in `c` from the start and end of `str`.
 * If the second argument is omitted, trims the characters, ` ` (space), `\t`,
 * `\r`, and `\n`.
 *
 * Returns the trimmed string.
 *
 * @function module:core#trim
 *
 * @param {string} str
 * The string to be trimmed.
 *
 * @param {string} [c]
 * The characters to be trimmed from the start and end of the string.
 *
 * @returns {string}
 */
static uc_value_t *
uc_trim(uc_vm_t *vm, size_t nargs)
{
	return uc_trim_common(vm, nargs, true, true);
}

/**
 * Trim any of the specified characters from the start of the string.
 * If the second argument is omitted, trims the characters ` ` (space), '\t',
 * '\r', and '\n'.
 *
 * Returns the left trimmed string.
 *
 * @function module:core#ltrim
 *
 * @param {string} s
 * The input string.
 *
 * @param {string} [c]
 * The characters to trim.
 *
 * @returns {string}
 *
 * @example
 * ltrim("  foo  \n")     // "foo  \n"
 * ltrim("--bar--", "-")  // "bar--"
 */
static uc_value_t *
uc_ltrim(uc_vm_t *vm, size_t nargs)
{
	return uc_trim_common(vm, nargs, true, false);
}

/**
 * Trim any of the specified characters from the end of the string.
 * If the second argument is omitted, trims the characters ` ` (space), '\t',
 * '\r', and '\n'.
 *
* Returns the right trimmed string.
 *
 * @function module:core#rtrim
 *
 * @param {string} str
 * The input string.
 *
 * @param {string} [c]
 * The characters to trim.
 *
 * @returns {string}
 *
 * @example
 * rtrim("  foo  \n")     // "  foo"
 * rtrim("--bar--", "-")  // "--bar"
 */
static uc_value_t *
uc_rtrim(uc_vm_t *vm, size_t nargs)
{
	return uc_trim_common(vm, nargs, false, true);
}

enum {
	FMT_F_ALT   = (1 << 0),
	FMT_F_ZERO  = (1 << 1),
	FMT_F_LEFT  = (1 << 2),
	FMT_F_SPACE = (1 << 3),
	FMT_F_SIGN  = (1 << 4),
	FMT_F_WIDTH = (1 << 5),
	FMT_F_PREC  = (1 << 6),
};

enum {
	FMT_C_NONE = (1 << 0),
	FMT_C_INT  = (1 << 1),
	FMT_C_UINT = (1 << 2),
	FMT_C_DBL  = (1 << 3),
	FMT_C_CHR  = (1 << 4),
	FMT_C_STR  = (1 << 5),
	FMT_C_JSON = (1 << 6),
};

static void
uc_printf_common(uc_vm_t *vm, size_t nargs, uc_stringbuf_t *buf)
{
	char *s, sfmt[sizeof("%#0- +0123456789.0123456789%")];
	uint32_t conv, flags, width, precision;
	uc_value_t *fmt = uc_fn_arg(0), *arg;
	const char *fstr, *last, *p, *cfmt;
	size_t argidx = 1, argpos, sfmtlen;
	uint64_t u;
	int64_t n;
	double d;

	if (ucv_type(fmt) == UC_STRING)
		fstr = ucv_string_get(fmt);
	else
		fstr = "";

	for (last = p = fstr; *p; p++) {
		if (*p == '%') {
			ucv_stringbuf_addstr(buf, last, p - last);

			last = p++;

			flags = 0;
			width = 0;
			precision = 0;

			argpos = argidx;

			if (*p >= '1' && *p <= '9') {
				while (isdigit(*p))
					width = width * 10 + (*p++ - '0');

				/* if a dollar sign follows, this is an argument index */
				if (*p == '$') {
					argpos = width;
					width = 0;
					p++;
				}

				/* otherwise skip to parsing precision, flags can't possibly follow */
				else {
					flags |= FMT_F_WIDTH;
					goto parse_precision;
				}
			}

			while (*p != '\0' && strchr("#0- +", *p)) {
				switch (*p++) {
				case '#': flags |= FMT_F_ALT;   break;
				case '0': flags |= FMT_F_ZERO;  break;
				case '-': flags |= FMT_F_LEFT;  break;
				case ' ': flags |= FMT_F_SPACE; break;
				case '+': flags |= FMT_F_SIGN;  break;
				}
			}

			if (*p >= '1' && *p <= '9') {
				while (isdigit(*p))
					width = width * 10 + (*p++ - '0');

				flags |= FMT_F_WIDTH;
			}

parse_precision:
			if (*p == '.') {
				p++;

				if (*p == '-') {
					p++;

					while (isdigit(*p))
						p++;
				}
				else {
					while (isdigit(*p))
						precision = precision * 10 + (*p++ - '0');
				}

				flags |= FMT_F_PREC;
			}

			switch (*p) {
			case 'd':
			case 'i':
				conv = FMT_C_INT;
				flags &= ~FMT_F_PREC;
				cfmt = PRId64;
				break;

			case 'o':
				conv = FMT_C_UINT;
				flags &= ~FMT_F_PREC;
				cfmt = PRIo64;
				break;

			case 'u':
				conv = FMT_C_UINT;
				flags &= ~FMT_F_PREC;
				cfmt = PRIu64;
				break;

			case 'x':
				conv = FMT_C_UINT;
				flags &= ~FMT_F_PREC;
				cfmt = PRIx64;
				break;

			case 'X':
				conv = FMT_C_UINT;
				flags &= ~FMT_F_PREC;
				cfmt = PRIX64;
				break;

			case 'e':
				conv = FMT_C_DBL;
				cfmt = "e";
				break;

			case 'E':
				conv = FMT_C_DBL;
				cfmt = "E";
				break;

			case 'f':
				conv = FMT_C_DBL;
				cfmt = "f";
				break;

			case 'F':
				conv = FMT_C_DBL;
				cfmt = "F";
				break;

			case 'g':
				conv = FMT_C_DBL;
				cfmt = "g";
				break;

			case 'G':
				conv = FMT_C_DBL;
				cfmt = "G";
				break;

			case 'c':
				conv = FMT_C_CHR;
				flags &= ~FMT_F_PREC;
				cfmt = "c";
				break;

			case 's':
				conv = FMT_C_STR;
				flags &= ~FMT_F_ZERO;
				cfmt = "s";
				break;

			case 'J':
				conv = FMT_C_JSON;

				if (flags & FMT_F_PREC) {
					flags &= ~FMT_F_PREC;
					precision++;
				}

				cfmt = "s";
				break;

			case '%':
				conv = FMT_C_NONE;
				flags = 0;
				cfmt = "%";
				break;

			case '\0':
				p--;
				/* fall through */

			default:
				continue;
			}

			sfmtlen = 0;
			sfmt[sfmtlen++] = '%';

			if (flags & FMT_F_ALT)   sfmt[sfmtlen++] = '#';
			if (flags & FMT_F_ZERO)  sfmt[sfmtlen++] = '0';
			if (flags & FMT_F_LEFT)  sfmt[sfmtlen++] = '-';
			if (flags & FMT_F_SPACE) sfmt[sfmtlen++] = ' ';
			if (flags & FMT_F_SIGN)  sfmt[sfmtlen++] = '+';

			if (flags & FMT_F_WIDTH)
				sfmtlen += snprintf(&sfmt[sfmtlen], sizeof(sfmt) - sfmtlen, "%" PRIu32, width);

			if (flags & FMT_F_PREC)
				sfmtlen += snprintf(&sfmt[sfmtlen], sizeof(sfmt) - sfmtlen, ".%" PRIu32, precision);

			snprintf(&sfmt[sfmtlen], sizeof(sfmt) - sfmtlen, "%s", cfmt);

			switch (conv) {
			case FMT_C_NONE:
				ucv_stringbuf_addstr(buf, cfmt, strlen(cfmt));
				break;

			case FMT_C_INT:
				argidx++;
				arg = uc_fn_arg(argpos);
				n = ucv_to_integer(arg);

				if (errno == ERANGE)
					n = (int64_t)ucv_to_unsigned(arg);

				ucv_stringbuf_printf(buf, sfmt, n);
				break;

			case FMT_C_UINT:
				argidx++;
				arg = uc_fn_arg(argpos);
				u = ucv_to_unsigned(arg);

				if (errno == ERANGE)
					u = (uint64_t)ucv_to_integer(arg);

				ucv_stringbuf_printf(buf, sfmt, u);
				break;

			case FMT_C_DBL:
				argidx++;
				d = ucv_to_double(uc_fn_arg(argpos));
				ucv_stringbuf_printf(buf, sfmt, d);
				break;

			case FMT_C_CHR:
				argidx++;
				n = ucv_to_integer(uc_fn_arg(argpos));
				ucv_stringbuf_printf(buf, sfmt, (int)n);
				break;

			case FMT_C_STR:
				argidx++;
				arg = uc_fn_arg(argpos);

				switch (ucv_type(arg)) {
				case UC_STRING:
					ucv_stringbuf_printf(buf, sfmt, ucv_string_get(arg));
					break;

				case UC_NULL:
					ucv_stringbuf_append(buf, "(null)");
					break;

				default:
					s = ucv_to_string(vm, arg);
					ucv_stringbuf_printf(buf, sfmt, s ? s : "(null)");
					free(s);
				}

				break;

			case FMT_C_JSON:
				argidx++;
				s = ucv_to_jsonstring_formatted(vm,
					uc_fn_arg(argpos),
					precision > 0 ? (precision > 1 ? ' ' : '\t') : '\0',
					precision > 0 ? (precision > 1 ? precision - 1 : 1) : 0);

				ucv_stringbuf_printf(buf, sfmt, s ? s : "null");
				free(s);
				break;
			}

			last = p + 1;
		}
	}

	ucv_stringbuf_addstr(buf, last, p - last);
}

/**
 * Formats the given arguments according to the given format string.
 *
 * See `printf()` for details.
 *
 * Returns the formatted string.
 *
 * @function module:core#sprintf
 *
 * @param {string} fmt
 * The format string.
 *
 * @param {...*}
 * Arguments to be formatted.
 *
 * @returns {string}
 *
 * @example
 * sprintf("Hello %s", "world");    // "Hello world"
 * sprintf("%08x", 123);            // "0000007b"
 * sprintf("%c%c%c", 65, 98, 99);   // "Abc"
 * sprintf("%g", 10 / 3.0);         // "3.33333"
 * sprintf("%2$d %1$d", 12, 34);    // "34 12"
 * sprintf("%J", [1,2,3]);          // "[1,2,3]"
 */
static uc_value_t *
uc_sprintf(uc_vm_t *vm, size_t nargs)
{
	uc_stringbuf_t *buf = ucv_stringbuf_new();

	uc_printf_common(vm, nargs, buf);

	return ucv_stringbuf_finish(buf);
}

/**
 * Formats the given arguments according to the given format string and outputs
 * the result to stdout.
 *
 * Ucode supports a restricted subset of the formats allowed by the underlying
 * libc's `printf()` implementation, namely it allows the `d`, `i`, `o`, `u`,
 * `x`, `X`, `e`, `E`, `f`, `F`, `g`, `G`, `c` and `s` conversions.
 *
 * Additionally, an ucode specific `J` format is implemented, which causes the
 * corresponding value to be formatted as JSON string. By prefixing the `J`
 * format letter with a precision specifier, the resulting JSON output will be
 * pretty printed. A precision of `0` will use tabs for indentation, any other
 * positive precision will use that many spaces for indentation while a negative
 * or omitted precision specifier will turn off pretty printing.
 *
 * Other format specifiers such as `n` or `z` are not accepted and returned
 * verbatim. Format specifiers including `*` directives are rejected as well.
 *
 * Returns the number of bytes written to the standard output.
 *
 * @function module:core#printf
 *
 * @param {string} fmt
 * The format string.
 *
 * @param {...*}
 * Arguments to be formatted.
 *
 * @returns {number}
 *
 * @example
 * {%
 *   printf("Hello %s\n", "world");  // Hello world
 *   printf("%08x\n", 123);          // 0000007b
 *   printf("%c%c%c\n", 65, 98, 99); // Abc
 *   printf("%g\n", 10 / 3.0);       // 3.33333
 *   printf("%2$d %1$d\n", 12, 34);  // 34 12
 *   printf("%J", [1,2,3]);          // [ 1, 2, 3 ]
 *
 *   printf("%.J", [1,2,3]);
 *   // [
 *   //         1,
 *   //         2,
 *   //         3
 *   // ]
 *
 *   printf("%.2J", [1,2,3]);
 *   // [
 *   //   1,
 *   //   2,
 *   //   3
 *   // ]
 * %}
 */
static uc_value_t *
uc_printf(uc_vm_t *vm, size_t nargs)
{
	uc_stringbuf_t *buf = xprintbuf_new();
	size_t len;

	uc_printf_common(vm, nargs, buf);

	len = fwrite(buf->buf, 1, printbuf_length(buf), vm->output);

	printbuf_free(buf);

	return ucv_int64_new(len);
}

static bool
uc_require_so(uc_vm_t *vm, const char *path, uc_value_t **res)
{
	void (*init)(uc_vm_t *, uc_value_t *);
	uc_value_t *scope;
	struct stat st;
	void *dlh;

	if (stat(path, &st))
		return false;

	dlerror();
	dlh = dlopen(path, RTLD_LAZY|RTLD_LOCAL);

	if (!dlh) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Unable to dlopen file '%s': %s", path, dlerror());

		return true;
	}

	*(void **)(&init) = dlsym(dlh, "uc_module_entry");

	if (!init) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Module '%s' provides no 'uc_module_entry' function", path);

		return true;
	}

	scope = ucv_object_new(vm);

	init(vm, scope);

	*res = scope;

	return true;
}

static uc_value_t *
uc_loadfile(uc_vm_t *vm, size_t nargs);

static uc_value_t *
uc_callfunc(uc_vm_t *vm, size_t nargs);

static bool
uc_require_ucode(uc_vm_t *vm, const char *path, uc_value_t *scope, uc_value_t **res, bool raw_mode)
{
	uc_parse_config_t config = *vm->config, *prev_config = vm->config;
	uc_value_t *closure;
	struct stat st;

	if (stat(path, &st))
		return false;

	config.raw_mode = raw_mode;
	vm->config = &config;

	uc_vm_stack_push(vm, ucv_string_new(path));

	closure = uc_loadfile(vm, 1);

	ucv_put(uc_vm_stack_pop(vm));

	if (closure) {
		uc_vm_stack_push(vm, closure);
		uc_vm_stack_push(vm, NULL);
		uc_vm_stack_push(vm, scope);

		*res = uc_callfunc(vm, 3);

		uc_vm_stack_pop(vm);
		uc_vm_stack_pop(vm);
		uc_vm_stack_pop(vm);
	}

	vm->config = prev_config;

	return true;
}

static bool
uc_require_path(uc_vm_t *vm, const char *path_template, const char *name, uc_value_t **res, bool so_only)
{
	uc_stringbuf_t *buf = xprintbuf_new();
	const char *p, *q, *last;
	uc_value_t *modtable;
	bool rv;

	modtable = ucv_property_get(uc_vm_scope_get(vm), "modules");
	*res = ucv_get(ucv_object_get(modtable, name, &rv));

	if (rv)
		goto out;

	p = strchr(path_template, '*');

	if (!p)
		goto out;

	ucv_stringbuf_addstr(buf, path_template, p - path_template);

	for (q = last = name;; q++) {
		if (*q == '.' || *q == '\0') {
			ucv_stringbuf_addstr(buf, last, q - last);

			if (*q)
				ucv_stringbuf_append(buf, "/");
			else
				ucv_stringbuf_addstr(buf, p + 1, strlen(p + 1));

			if (*q == '\0')
				break;

			last = q + 1;
		}
		else if (!isalnum(*q) && *q != '_') {
			goto out;
		}
	}

	if (!strcmp(p + 1, ".so"))
		rv = uc_require_so(vm, buf->buf, res);
	else if (!strcmp(p + 1, ".uc") && !so_only)
		rv = uc_require_ucode(vm, buf->buf, NULL, res, true);

	if (rv)
		ucv_object_add(modtable, name, ucv_get(*res));

out:
	printbuf_free(buf);

	return rv;
}

uc_value_t *
uc_require_library(uc_vm_t *vm, uc_value_t *nameval, bool so_only)
{
	uc_value_t *search, *se, *res;
	size_t arridx, arrlen;
	const char *name;

	if (ucv_type(nameval) != UC_STRING)
		return NULL;

	name = ucv_string_get(nameval);
	search = ucv_property_get(uc_vm_scope_get(vm), "REQUIRE_SEARCH_PATH");

	if (ucv_type(search) != UC_ARRAY) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Global require search path not set");

		return NULL;
	}

	for (arridx = 0, arrlen = ucv_array_length(search); arridx < arrlen; arridx++) {
		se = ucv_array_get(search, arridx);

		if (ucv_type(se) != UC_STRING)
			continue;

		if (uc_require_path(vm, ucv_string_get(se), name, &res, so_only))
			return res;
	}

	uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
	                      "No module named '%s' could be found", name);

	return NULL;
}

/**
 * Load and evaluate ucode scripts or shared library extensions.
 *
 * The `require()` function expands each member of the global
 * `REQUIRE_SEARCH_PATH` array to a filesystem path by replacing the `*`
 * placeholder with a slash-separated version of the given dotted module name
 * and subsequently tries to load a file at the resulting location.
 *
 * If a file is found at one of the search path locations, it is compiled and
 * evaluated or loaded via the C runtime's `dlopen()` function, depending on
 * whether the found file is a ucode script or a compiled dynamic library.
 *
 * The resulting program function of the compiled/loaded module is then
 * subsequently executed with the current global environment, without a `this`
 * context and without arguments.
 *
 * Finally, the return value of the invoked program function is returned back
 * by `require()` to the caller.
 *
 * By default, modules are cached in the global `modules` dictionary and
 * subsequent attempts to require the same module will return the cached module
 * dictionary entry without re-evaluating the module.
 *
 * To force reloading a module, the corresponding entry from the global
 * `modules` dictionary can be deleted.
 *
 * To preload a module or to provide a "virtual" module without a corresponding
 * filesystem resource, an entry can be manually added to the global `modules`
 * dictionary.
 *
 * Summarized, the `require()` function can be roughly described by the
 * following code:
 *
 * ```
 * function require(name) {
 *     if (exists(modules, name))
 *         return modules[name];
 *
 *     for (const item in REQUIRE_SEARCH_PATH) {
 *         const modpath = replace(item, '*', replace(name, '.', '/'));
 *         const entryfunc = loadfile(modpath, { raw_mode: true });
 *
 *         if (entryfunc) {
 *             const modval = entryfunc();
 *             modules[name] = modval;
 *
 *             return modval;
 *         }
 *     }
 *
 *     die(`Module ${name} not found`);
 * }
 * ```
 *
 * Due to the fact that `require()` is a runtime operation, module source code
 * is only lazily evaluated/loaded upon invoking the first require invocation,
 * which might lead to situations where errors in module sources are only
 * reported much later throughout the program execution. Unless runtime loading
 * of modules is absolutely required, e.g. to conditionally load extensions, the
 * compile time
 * {@link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/import#named_import|`import` syntax}
 * should be preferred.
 *
 * Returns the module value (typically an object) on success.
 *
 * Throws an exception if the module function threw an exception.
 *
 * Throws an exception if no matching module could be found, if the module
 * contains syntax errors or upon other I/O related problems.
 *
 * @function module:core#require
 *
 * @param {string} name
 * The name of the module to require in dotted notation.
 *
 * @returns {*}
 *
 * @example
 * // Require the `example/acme.uc` or `example/acme.so` module
 * const acme = require('example.acme');
 *
 * // Requiring the same name again will yield the cached instance
 * const acme2 = require('example.acme');
 * assert(acme === acme2);
 *
 * // Deleting the module dictionary entry will force a reload
 * delete modules['example.acme'];
 * const acme3 = require('example.acme');
 * assert(acme !== acme3);
 *
 * // Preloading a "virtual" module
 * modules['example.test'] = {
 *   hello: function() { print("This is the example module\n"); }
 * };
 *
 * const test = require('example.test');
 * test.hello();  // will print "This is the example module"
 */
static uc_value_t *
uc_require(uc_vm_t *vm, size_t nargs)
{
	return uc_require_library(vm, uc_fn_arg(0), false);
}

/**
 * Convert the given IP address string to an array of byte values.
 *
 * IPv4 addresses result in arrays of 4 integers while IPv6 ones in arrays
 * containing 16 integers. The resulting array can be turned back into IP
 * address strings using the inverse `arrtoip()` function.
 *
 * Returns an array containing the address byte values.
 * Returns `null` if the given argument is not a string or an invalid IP.
 *
 * @function module:core#iptoarr
 *
 * @param {string} address
 * The IP address string to convert.
 *
 * @returns {?number[]}
 *
 * @example
 * iptoarr("192.168.1.1")              // [ 192, 168, 1, 1 ]
 * iptoarr("fe80::fc54:ff:fe82:abbd")  // [ 254, 128, 0, 0, 0, 0, 0, 0, 252, 84,
 *                                     //   0, 255, 254, 130, 171, 189 ])
 * iptoarr("foo")                      // null (invalid address)
 * iptoarr(123)                        // null (not a string)
 */
static uc_value_t *
uc_iptoarr(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *ip = uc_fn_arg(0);
	uc_value_t *res;
	union {
		uint8_t u8[4];
		struct in_addr in;
		struct in6_addr in6;
	} a;
	int i;

	if (ucv_type(ip) != UC_STRING)
		return NULL;

	if (inet_pton(AF_INET6, ucv_string_get(ip), &a)) {
		res = ucv_array_new(vm);

		for (i = 0; i < 16; i++)
			ucv_array_push(res, ucv_int64_new(a.in6.s6_addr[i]));

		return res;
	}
	else if (inet_pton(AF_INET, ucv_string_get(ip), &a)) {
		res = ucv_array_new(vm);

		ucv_array_push(res, ucv_int64_new(a.u8[0]));
		ucv_array_push(res, ucv_int64_new(a.u8[1]));
		ucv_array_push(res, ucv_int64_new(a.u8[2]));
		ucv_array_push(res, ucv_int64_new(a.u8[3]));

		return res;
	}

	return NULL;
}

static int
check_byte(uc_value_t *v)
{
	int n;

	if (ucv_type(v) != UC_INTEGER)
		return -1;

	n = ucv_int64_get(v);

	if (n < 0 || n > 255)
		return -1;

	return n;
}

/**
 * Convert the given input array of byte values to an IP address string.
 *
 * Input arrays of length 4 are converted to IPv4 addresses, arrays of length 16
 * to IPv6 ones. All other lengths are rejected. If any array element is not an
 * integer or exceeds the range 0..255 (inclusive), the array is rejected.
 *
 * Returns a string containing the formatted IP address.
 * Returns `null` if the input array was invalid.
 *
 * @function module:core#arrtoip
 *
 * @param {number[]} arr
 * The byte array to convert into an IP address string.
 *
 * @returns {?string}
 *
 * @example
 * arrtoip([ 192, 168, 1, 1 ])   // "192.168.1.1"
 * arrtoip([ 254, 128, 0, 0, 0, 0, 0, 0, 252, 84, 0, 255, 254, 130, 171, 189 ])
 *                               // "fe80::fc54:ff:fe82:abbd"
 * arrtoip([ 1, 2, 3])           // null (invalid length)
 * arrtoip([ 1, "2", -5, 300 ])  // null (invalid values)
 * arrtoip("123")                // null (not an array)
 */
static uc_value_t *
uc_arrtoip(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *arr = uc_fn_arg(0);
	union {
		uint8_t u8[4];
		struct in6_addr in6;
	} a;
	char buf[INET6_ADDRSTRLEN];
	int i, n;

	if (ucv_type(arr) != UC_ARRAY)
		return NULL;

	switch (ucv_array_length(arr)) {
	case 4:
		for (i = 0; i < 4; i++) {
			n = check_byte(ucv_array_get(arr, i));

			if (n < 0)
				return NULL;

			a.u8[i] = n;
		}

		inet_ntop(AF_INET, &a, buf, sizeof(buf));

		return ucv_string_new(buf);

	case 16:
		for (i = 0; i < 16; i++) {
			n = check_byte(ucv_array_get(arr, i));

			if (n < 0)
				return NULL;

			a.in6.s6_addr[i] = n;
		}

		inet_ntop(AF_INET6, &a, buf, sizeof(buf));

		return ucv_string_new(buf);

	default:
		return NULL;
	}
}

/**
 * Match the given string against the regular expression pattern specified as
 * the second argument.
 *
 * If the passed regular expression uses the `g` flag, the return value will be
 * an array of arrays describing all found occurrences within the string.
 *
 * Without the `g` modifier, an array describing the first match is returned.
 *
 * Returns `null` if the pattern was not found within the given string.
 *
 * @function module:core#match
 *
 * @param {string} str
 * The string to be matched against the pattern.
 *
 * @param {RegExp} pattern
 * The regular expression pattern.
 *
 * @returns {?Array}
 *
 * @example
 * match("foobarbaz", /b.(.)/)   // ["bar", "r"]
 * match("foobarbaz", /b.(.)/g)  // [["bar", "r"], ["baz", "z"]]
 */
static uc_value_t *
uc_match(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *subject = uc_fn_arg(0);
	uc_value_t *pattern = uc_fn_arg(1);
	uc_value_t *rv = NULL, *m;
	regmatch_t *pmatch = NULL;
	int eflags = 0, res;
	uc_regexp_t *re;
	bool freeable;
	char *p;
	size_t i;

	if (ucv_type(pattern) != UC_REGEXP || !subject)
		return NULL;

	re = (uc_regexp_t *)pattern;

	pmatch = calloc(1 + re->regexp.re_nsub, sizeof(regmatch_t));

	if (!pmatch)
		return NULL;

	p = uc_cast_string(vm, &subject, &freeable);

	while (true) {
		res = regexec(&re->regexp, p, 1 + re->regexp.re_nsub, pmatch, eflags);

		if (res == REG_NOMATCH)
			break;

		m = ucv_array_new(vm);

		for (i = 0; i < 1 + re->regexp.re_nsub; i++) {
			if (pmatch[i].rm_so != -1)
				ucv_array_push(m,
					ucv_string_new_length(p + pmatch[i].rm_so,
					                      pmatch[i].rm_eo - pmatch[i].rm_so));
			else
				ucv_array_push(m, NULL);
		}

		if (re->global) {
			if (!rv)
				rv = ucv_array_new(vm);

			ucv_array_push(rv, m);

			if (pmatch[0].rm_so != pmatch[0].rm_eo)
				p += pmatch[0].rm_eo;
			else if (*p)
				p++;
			else
				break;

			eflags |= REG_NOTBOL;
		}
		else {
			rv = m;
			break;
		}
	}

	free(pmatch);

	if (freeable)
		free(p);

	return rv;
}

static void
uc_replace_cb(uc_vm_t *vm, uc_value_t *func,
              const char *subject, regmatch_t *pmatch, size_t plen,
              uc_stringbuf_t *resbuf)
{
	uc_value_t *rv;
	size_t i;

	uc_vm_ctx_push(vm);
	uc_vm_stack_push(vm, ucv_get(func));

	for (i = 0; i < plen; i++) {
		if (pmatch[i].rm_so != -1)
			uc_vm_stack_push(vm,
				ucv_string_new_length(subject + pmatch[i].rm_so,
				                      pmatch[i].rm_eo - pmatch[i].rm_so));
		else
			uc_vm_stack_push(vm, NULL);
	}

	if (uc_vm_call(vm, true, i) == EXCEPTION_NONE) {
		rv = uc_vm_stack_pop(vm);

		ucv_to_stringbuf(vm, resbuf, rv, false);

		ucv_put(rv);
	}
}

static void
uc_replace_str(uc_vm_t *vm, uc_value_t *str,
               const char *subject, regmatch_t *pmatch, size_t plen,
               uc_stringbuf_t *resbuf)
{
	bool esc = false;
	char *p, *r;
	uint8_t i;

	for (p = r = ucv_to_string(vm, str); *p; p++) {
		if (esc) {
			switch (*p) {
			case '&':
				if (pmatch[0].rm_so != -1)
					ucv_stringbuf_addstr(resbuf,
						subject + pmatch[0].rm_so,
						pmatch[0].rm_eo - pmatch[0].rm_so);
				break;

			case '`':
				if (pmatch[0].rm_so != -1)
					ucv_stringbuf_addstr(resbuf, subject, pmatch[0].rm_so);
				break;

			case '\'':
				if (pmatch[0].rm_so != -1)
					ucv_stringbuf_addstr(resbuf,
						subject + pmatch[0].rm_eo,
						strlen(subject + pmatch[0].rm_eo));
				break;

			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				i = *p - '0';
				if (i < plen && pmatch[i].rm_so != -1) {
					ucv_stringbuf_addstr(resbuf,
						subject + pmatch[i].rm_so,
						pmatch[i].rm_eo - pmatch[i].rm_so);
				}
				else {
					ucv_stringbuf_append(resbuf, "$");
					ucv_stringbuf_addstr(resbuf, p, 1);
				}
				break;

			case '$':
				ucv_stringbuf_append(resbuf, "$");
				break;

			default:
				ucv_stringbuf_append(resbuf, "$");
				ucv_stringbuf_addstr(resbuf, p, 1);
			}

			esc = false;
		}
		else if (*p == '$') {
			esc = true;
		}
		else {
			ucv_stringbuf_addstr(resbuf, p, 1);
		}
	}

	free(r);
}

/**
 * Replace occurrences of the specified pattern in the string passed as the
 * first argument.
 *
 * - The pattern value may be either a regular expression or a plain string.
 * - The replace value may be a function which is invoked for each found pattern
 *   or any other value which is converted into a plain string and used as
 *   replacement.
 * - When an optional limit is specified, substitutions are performed only that
 *   many times.
 * - If the pattern is a regular expression and not using the `g` flag, then
 *   only the first occurrence in the string is replaced.
 * - If the `g` flag is used or if the pattern is not a regular expression, all
 *   occurrences are replaced.
 * - If the replace value is a callback function, it is invoked with the found
 *   substring as the first and any capture group values as subsequent
 *   parameters.
 * - If the replace value is a string, specific substrings are substituted
 *   before it is inserted into the result.
 *
 * Returns a new string with the pattern replaced.
 *
 * @function module:core#replace
 *
 * @param {string} str
 * The string in which to replace occurrences.
 *
 * @param {RegExp|string} pattern
 * The pattern to be replaced.
 *
 * @param {Function|string} replace
 * The replacement value.
 *
 * @param {number} [limit]
 * The optional limit of substitutions.
 *
 * @returns {string}
 *
 * @example
 * replace("barfoobaz", /(f)(o+)/g, "[$$|$`|$&|$'|$1|$2|$3]")  // bar[$|bar|foo|baz|f|oo|$3]baz
 * replace("barfoobaz", /(f)(o+)/g, uc)                        // barFOObaz
 * replace("barfoobaz", "a", "X")                              // bXrfoobXz
 * replace("barfoobaz", /(.)(.)(.)/g, function(m, c1, c2, c3) {
 *     return c3 + c2 + c1;
 * })                                                          // raboofzab
 * replace("aaaaa", "a", "x", 3)                               // xxxaa
 * replace("foo bar baz", /[ao]/g, "x", 3)                     // fxx bxr baz
 */
static uc_value_t *
uc_replace(uc_vm_t *vm, size_t nargs)
{
	char *sb = NULL, *pt = NULL, *p, *l;
	uc_value_t *subject = uc_fn_arg(0);
	uc_value_t *pattern = uc_fn_arg(1);
	uc_value_t *replace = uc_fn_arg(2);
	uc_value_t *limitval = uc_fn_arg(3);
	bool sb_freeable, pt_freeable;
	regmatch_t *pmatch = NULL;
	size_t pl, nmatch, limit;
	uc_regexp_t *re = NULL;
	uc_stringbuf_t *resbuf;
	int eflags = 0, res;

	if (!pattern || !subject || !replace)
		return NULL;

	nmatch = 1;

	if (ucv_type(pattern) == UC_REGEXP) {
		re = (uc_regexp_t *)pattern;
		nmatch += re->regexp.re_nsub;
	}

	pmatch = calloc(nmatch, sizeof(regmatch_t));

	if (!pmatch)
		return NULL;

	sb = uc_cast_string(vm, &subject, &sb_freeable);
	resbuf = ucv_stringbuf_new();
	limit = limitval ? ucv_uint64_get(limitval) : SIZE_MAX;

	if (re) {
		p = sb;

		while (limit > 0) {
			res = regexec(&re->regexp, p, nmatch, pmatch, eflags);

			if (res == REG_NOMATCH)
				break;

			ucv_stringbuf_addstr(resbuf, p, pmatch[0].rm_so);

			if (ucv_is_callable(replace))
				uc_replace_cb(vm, replace, p, pmatch, nmatch, resbuf);
			else
				uc_replace_str(vm, replace, p, pmatch, nmatch, resbuf);

			if (pmatch[0].rm_so != pmatch[0].rm_eo)
				p += pmatch[0].rm_eo;
			else if (*p)
				ucv_stringbuf_addstr(resbuf, p++, 1);
			else
				break;

			if (re->global)
				eflags |= REG_NOTBOL;
			else
				break;

			limit--;
		}

		ucv_stringbuf_addstr(resbuf, p, strlen(p));
	}
	else {
		pt = uc_cast_string(vm, &pattern, &pt_freeable);
		pl = strlen(pt);

		l = p = sb;

		while (limit > 0) {
			if (pl == 0 || !strncmp(p, pt, pl)) {
				ucv_stringbuf_addstr(resbuf, l, p - l);

				pmatch[0].rm_so = p - l;
				pmatch[0].rm_eo = pmatch[0].rm_so + pl;

				if (ucv_is_callable(replace))
					uc_replace_cb(vm, replace, l, pmatch, 1, resbuf);
				else
					uc_replace_str(vm, replace, l, pmatch, 1, resbuf);

				if (pl) {
					l = p + pl;
					p += pl - 1;
				}
				else {
					l = p;
				}

				limit--;
			}

			if (!*p++)
				break;
		}

		ucv_stringbuf_addstr(resbuf, l, strlen(l));

		if (pt_freeable)
			free(pt);
	}

	free(pmatch);

	if (sb_freeable)
		free(sb);

	return ucv_stringbuf_finish(resbuf);
}

static struct json_tokener *
uc_json_from_object(uc_vm_t *vm, uc_value_t *obj, json_object **jso)
{
	bool trail = false, eof = false;
	enum json_tokener_error err;
	struct json_tokener *tok;
	uc_value_t *rfn, *rbuf;
	uc_stringbuf_t *buf;

	rfn = ucv_property_get(obj, "read");

	if (!ucv_is_callable(rfn)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
		                      "Input object does not implement read() method");

		return NULL;
	}

	tok = xjs_new_tokener();

	while (true) {
		uc_vm_stack_push(vm, ucv_get(obj));
		uc_vm_stack_push(vm, ucv_get(rfn));
		uc_vm_stack_push(vm, ucv_int64_new(1024));

		if (uc_vm_call(vm, true, 1) != EXCEPTION_NONE) {
			json_tokener_free(tok);

			return NULL;
		}

		rbuf = uc_vm_stack_pop(vm);

		/* check EOF */
		eof = (rbuf == NULL || (ucv_type(rbuf) == UC_STRING && ucv_string_length(rbuf) == 0));

		/* on EOF, stop parsing unless trailing garbage was detected which handled below */
		if (eof && !trail) {
			ucv_put(rbuf);

			/* Didn't parse a complete object yet, possibly a non-delimitted atomic value
			   such as `null`, `true` etc. - nudge parser by sending final zero byte.
			   See json-c issue #681 <https://github.com/json-c/json-c/issues/681> */
			if (json_tokener_get_error(tok) == json_tokener_continue)
				*jso = json_tokener_parse_ex(tok, "\0", 1);

			break;
		}

		if (trail || *jso) {
			uc_vm_raise_exception(vm, EXCEPTION_SYNTAX,
			                      "Trailing garbage after JSON data");

			json_tokener_free(tok);
			ucv_put(rbuf);

			return NULL;
		}

		if (ucv_type(rbuf) != UC_STRING) {
			buf = xprintbuf_new();
			ucv_to_stringbuf_formatted(vm, buf, rbuf, 0, '\0', 0);

			*jso = json_tokener_parse_ex(tok, buf->buf, printbuf_length(buf));

			trail = (json_tokener_get_error(tok) == json_tokener_success &&
			         json_tokener_get_parse_end(tok) < (size_t)printbuf_length(buf));

			printbuf_free(buf);
		}
		else {
			*jso = json_tokener_parse_ex(tok, ucv_string_get(rbuf), ucv_string_length(rbuf));

			trail = (json_tokener_get_error(tok) == json_tokener_success &&
			         json_tokener_get_parse_end(tok) < ucv_string_length(rbuf));
		}

		ucv_put(rbuf);

		err = json_tokener_get_error(tok);

		if (err != json_tokener_success && err != json_tokener_continue)
			break;
	}

	return tok;
}

static struct json_tokener *
uc_json_from_string(uc_vm_t *vm, uc_value_t *str, json_object **jso)
{
	struct json_tokener *tok = xjs_new_tokener();
	size_t i;
	char *p;

	/* NB: the len + 1 here is intentional to pass the terminating \0 byte
	 * to the json-c parser. This is required to work-around upstream
	 * issue #681 <https://github.com/json-c/json-c/issues/681> */
	*jso = json_tokener_parse_ex(tok, ucv_string_get(str), ucv_string_length(str) + 1);

	if (json_tokener_get_error(tok) == json_tokener_success) {
		p = ucv_string_get(str);

		for (i = json_tokener_get_parse_end(tok); i < ucv_string_length(str); i++) {
			if (!isspace(p[i])) {
				uc_vm_raise_exception(vm, EXCEPTION_SYNTAX,
				                      "Trailing garbage after JSON data");


				json_tokener_free(tok);

				return NULL;
			}
		}
	}

	return tok;
}

/**
 * Parse the given string or resource as JSON and return the resulting value.
 *
 * If the input argument is a plain string, it is directly parsed as JSON.
 *
 * If an array, object or resource value is given, this function will attempt to
 * invoke a `read()` method on it to read chunks of input text to incrementally
 * parse as JSON data. Reading will stop if the object's `read()` method returns
 * either `null` or an empty string.
 *
 * Throws an exception on parse errors, trailing garbage, or premature EOF.
 *
 * Returns the parsed JSON data.
 *
 * @function module:core#json
 *
 * @param {string} str_or_resource
 * The string or resource object to be parsed as JSON.
 *
 * @returns {*}
 *
 * @example
 * json('{"a":true, "b":123}')   // { "a": true, "b": 123 }
 * json('[1,2,')                 // Throws an exception
 *
 * import { open } from 'fs';
 * let fd = open('example.json', 'r');
 * json(fd);                     // will keep invoking `fd.read()` until EOF and
 *                               // incrementally parse each read chunk.
 *
 * let x = proto(
 *     [ '{"foo":', 'true, ', '"bar":', 'false}' ],
 *     { read: function() { return shift(this) } }
 * );
 * json(x);                      // will keep invoking `x.read()` until array
 *                               // is empty incrementally parse each piece
 *
 */
static uc_value_t *
uc_json(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *rv = NULL, *src = uc_fn_arg(0);
	struct json_tokener *tok = NULL;
	enum json_tokener_error err;
	json_object *jso = NULL;

	switch (ucv_type(src)) {
	case UC_STRING:
		tok = uc_json_from_string(vm, src, &jso);
		break;

	case UC_RESOURCE:
	case UC_OBJECT:
	case UC_ARRAY:
		tok = uc_json_from_object(vm, src, &jso);
		break;

	default:
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
		                      "Passed value is neither a string nor an object");
	}

	if (!tok)
		goto out;

	err = json_tokener_get_error(tok);

	if (err == json_tokener_continue) {
		uc_vm_raise_exception(vm, EXCEPTION_SYNTAX,
		                      "Unexpected end of string in JSON data");

		goto out;
	}
	else if (err != json_tokener_success) {
		uc_vm_raise_exception(vm, EXCEPTION_SYNTAX,
		                      "Failed to parse JSON string: %s",
		                      json_tokener_error_desc(err));

		goto out;
	}

	rv = ucv_from_json(vm, jso);

out:
	if (tok)
		json_tokener_free(tok);

	json_object_put(jso);

	return rv;
}

static char *
include_path(const char *curpath, const char *incpath)
{
	char *dup, *res;
	int len;

	if (*incpath == '/')
		return realpath(incpath, NULL);

	dup = curpath ? strrchr(curpath, '/') : NULL;

	if (dup)
		len = asprintf(&res, "%.*s/%s", (int)(dup - curpath), curpath, incpath);
	else
		len = asprintf(&res, "./%s", incpath);

	if (len == -1)
		return NULL;

	dup = realpath(res, NULL);

	free(res);

	return dup;
}

static uc_value_t *
uc_include_common(uc_vm_t *vm, size_t nargs, bool raw_mode)
{
	uc_value_t *path = uc_fn_arg(0);
	uc_value_t *scope = uc_fn_arg(1);
	uc_value_t *rv = NULL, *sc = NULL;
	uc_closure_t *closure = NULL;
	size_t i;
	char *p;

	if (ucv_type(path) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
		                      "Passed filename is not a string");

		return NULL;
	}

	if (scope && ucv_type(scope) != UC_OBJECT) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
		                      "Passed scope value is not an object");

		return NULL;
	}

	/* find calling closure */
	for (i = vm->callframes.count; i > 0; i--) {
		closure = vm->callframes.entries[i - 1].closure;

		if (closure)
			break;
	}

	if (!closure)
		return NULL;

	p = include_path(uc_program_function_source(closure->function)->runpath, ucv_string_get(path));

	if (!p) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Include file not found");

		return NULL;
	}

	if (ucv_prototype_get(scope)) {
		sc = ucv_get(scope);
	}
	else if (scope) {
		sc = ucv_object_new(vm);

		ucv_object_foreach(scope, key, val)
			ucv_object_add(sc, key, ucv_get(val));

		ucv_prototype_set(sc, ucv_get(uc_vm_scope_get(vm)));
	}
	else {
		sc = ucv_get(uc_vm_scope_get(vm));
	}

	if (uc_require_ucode(vm, p, sc, &rv, raw_mode))
		ucv_put(rv);

	ucv_put(sc);
	free(p);

	return NULL;
}

/**
 * Evaluate and include the file at the given path and optionally override the
 * execution scope with the given scope object.
 *
 * By default, the file is executed within the same scope as the calling
 * `include()`, but by passing an object as the second argument, it is possible
 * to extend the scope available to the included file.
 *
 * This is useful to supply additional properties as global variables to the
 * included code. To sandbox included code, that is giving it only access to
 * explicitly provided properties, the `proto()` function can be used to create
 * a scope object with an empty prototype.
 *
 * @function module:core#include
 *
 * @param {string} path
 * The path to the file to be included.
 *
 * @param {Object} [scope]
 * The optional scope object to override the execution scope.
 *
 * @example
 * // Load and execute "foo.uc" immediately
 * include("./foo.uc")
 *
 * // Execute the "supplemental.ucode" in an extended scope and make the "foo"
 * // and "bar" properties available as global variables
 * include("./supplemental.uc", {
 *   foo: true,
 *   bar: 123
 * })
 *
 * // Execute the "untrusted.ucode" in a sandboxed scope and make the "foo" and
 * // "bar" variables as well as the "print" function available to it.
 * // By assigning an empty prototype object to the scope, included code has no
 * // access to other global values anymore.
 * include("./untrusted.uc", proto({
 *   foo: true,
 *   bar: 123,
 *   print: print
 * }, {}))
 */
static uc_value_t *
uc_include(uc_vm_t *vm, size_t nargs)
{
	return uc_include_common(vm, nargs, vm->config && vm->config->raw_mode);
}

/**
 * When invoked with a string value as the first argument, the function acts
 * like `include()` but captures the output of the included file as a string and
 * returns the captured contents.
 *
 * The second argument is treated as the scope.
 *
 * When invoked with a function value as the first argument, `render()` calls
 * the given function and passes all subsequent arguments to it.
 *
 * Any output produced by the called function is captured and returned as a
 * string. The return value of the called function is discarded.
 *
 * @function module:core#render
 *
 * @param {string|Function} path_or_func
 * The path to the file or the function to be rendered.
 *
 * @param {Object|*} [scope_or_fnarg1]
 * The optional scope or the first argument for the function.
 *
 * @param {*} [fnarg2]
 * The second argument for the function.
 *
 * @param {...*} [fnargN]
 * Additional arguments for the function.
 *
 * @returns {string}
 *
 * @example
 * // Renders template file with given scope and captures the output as a string
 * const output = render("./template.uc", { foo: "bar" });
 *
 * // Calls a function, captures the output, and returns it as a string
 * const result = render(function(name) {
 *     printf("Hello, %s!\n", name);
 * }, "Alice");
 */
static uc_value_t *
uc_render(uc_vm_t *vm, size_t nargs)
{
	uc_string_t hdr = { .header = { .type = UC_STRING, .refcount = 1 } };
	uc_string_t *ustr = NULL;
	FILE *mem, *prev;
	size_t len = 0;

	mem = open_memstream((char **)&ustr, &len);

	if (!mem)
		goto out;

	/* reserve space for uc_string_t header... */
	if (fwrite(&hdr, 1, sizeof(hdr), mem) != sizeof(hdr))
		goto out;

	/* divert VM output to memory fd */
	prev = vm->output;
	vm->output = mem;

	/* execute function */
	if (ucv_is_callable(uc_fn_arg(0)))
		(void) uc_vm_call(vm, false, nargs - 1);

	/* execute include */
	else
		(void) uc_include_common(vm, nargs, false);

	/* restore previous VM output */
	vm->output = prev;
	fclose(mem);

	/* update uc_string_t length */
	ustr->length = len - sizeof(*ustr);

	return &ustr->header;

out:
	uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
	                      "Unable to initialize output memory: %s",
	                      strerror(errno));

	if (mem)
		fclose(mem);

	free(ustr);

	return NULL;
}

/**
 * Print any of the given values to stderr. Arrays and objects are converted to
 * their JSON representation.
 *
 * Returns the amount of bytes printed.
 *
 * @function module:core#warn
 *
 * @param {...*} x
 * The values to be printed.
 *
 * @returns {number}
 *
 * @example
 * warn("Hello", "world");  // Print "Helloworld" to stderr
 * warn({ key: "value" });  // Print JSON representation of the object to stderr
 */
static uc_value_t *
uc_warn(uc_vm_t *vm, size_t nargs)
{
	return uc_print_common(vm, nargs, stderr);
}

/**
 * Executes the given command, waits for completion, and returns the resulting
 * exit code.
 *
 * The command argument may be either a string, in which case it is passed to
 * `/bin/sh -c`, or an array, which is directly converted into an `execv()`
 * argument vector.
 *
 *  - If the program terminated normally, a positive integer holding the
 *    program's `exit()` code is returned.
 *  - If the program was terminated by an uncaught signal, a negative signal
 *    number is returned.
 *  - If the optional timeout argument is specified, the program is terminated
 *    by `SIGKILL` after that many milliseconds if it doesn't complete within
 *    the timeout.
 *
 * Omitting the timeout argument or passing `0` disables the command timeout.
 *
 * Returns the program exit code.
 *
 * @function module:core#system
 *
 * @param {string|Array} command
 * The command to be executed.
 *
 * @param {number} [timeout]
 * The optional timeout in milliseconds.
 *
 * @returns {number}
 *
 * @example
 * // Execute through `/bin/sh`
 * // prints "Hello world" to stdout and returns 3
 * system("echo 'Hello world' && exit 3");
 *
 * // Execute argument vector
 * // prints the UNIX timestamp to stdout and returns 0
 * system(["/usr/bin/date", "+%s"]);
 *
 * // Apply a timeout
 * // returns -9
 * system("sleep 3 && echo 'Success'", 1000);
 */
static uc_value_t *
uc_system(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *cmdline = uc_fn_arg(0);
	uc_value_t *timeout = uc_fn_arg(1);
	const char **arglist, *fn;
	sigset_t sigmask, sigomask;
	struct timespec ts;
	size_t i, len;
	int64_t tms;
	pid_t cld;
	int rc;

	if (timeout && (ucv_type(timeout) != UC_INTEGER || ucv_int64_get(timeout) < 0)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
		                      "Invalid timeout specified");

		return NULL;
	}

	switch (ucv_type(cmdline)) {
	case UC_STRING:
		arglist = xalloc(sizeof(*arglist) * 4);
		arglist[0] = xstrdup("/bin/sh");
		arglist[1] = xstrdup("-c");
		arglist[2] = ucv_to_string(vm, cmdline);
		arglist[3] = NULL;
		break;

	case UC_ARRAY:
		len = ucv_array_length(cmdline);

		if (len == 0) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			                      "Passed command array is empty");

			return NULL;
		}

		arglist = xalloc(sizeof(*arglist) * (len + 1));

		for (i = 0; i < len; i++)
			arglist[i] = ucv_to_string(vm, ucv_array_get(cmdline, i));

		arglist[i] = NULL;

		break;

	default:
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
		                      "Passed command is neither string nor array");

		return NULL;
	}

	tms = timeout ? ucv_int64_get(timeout) : 0;

	if (tms > 0) {
		sigemptyset(&sigmask);
		sigaddset(&sigmask, SIGCHLD);

		if (sigprocmask(SIG_BLOCK, &sigmask, &sigomask) < 0) {
			fn = "sigprocmask";
			goto fail;
		}
	}

	cld = fork();

	switch (cld) {
	case -1:
		fn = "fork";
		goto fail;

	case 0:
		execvp(arglist[0], (char * const *)arglist);
		exit(-1);

		break;

	default:
		if (tms > 0) {
			ts.tv_sec = tms / 1000;
			ts.tv_nsec = (tms % 1000) * 1000000;

			while (1) {
				if (sigtimedwait(&sigmask, NULL, &ts) < 0) {
					if (errno == EINTR)
						continue;

					if (errno != EAGAIN) {
						fn = "sigtimedwait";
						goto fail;
					}

					kill(cld, SIGKILL);
				}

				break;
			}
		}

		while (waitpid(cld, &rc, 0) < 0) {
			if (errno == EINTR)
				continue;

			fn = "waitpid";
			goto fail;
		}

		if (tms > 0)
			sigprocmask(SIG_SETMASK, &sigomask, NULL);

		for (i = 0; arglist[i]; i++)
			free((char *)arglist[i]);

		free(arglist);

		if (WIFEXITED(rc))
			return ucv_int64_new(WEXITSTATUS(rc));
		else if (WIFSIGNALED(rc))
			return ucv_int64_new(-WTERMSIG(rc));
		else if (WIFSTOPPED(rc))
			return ucv_int64_new(-WSTOPSIG(rc));

		return NULL;
	}

fail:
	if (tms > 0)
		sigprocmask(SIG_SETMASK, &sigomask, NULL);

	for (i = 0; arglist[i]; i++)
		free((char *)arglist[i]);

	free(arglist);

	uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
	                      "%s(): %s", fn, strerror(errno));

	return NULL;
}

/**
 * Enables or disables VM opcode tracing.
 *
 * When invoked with a positive non-zero level, opcode tracing is enabled and
 * debug information is printed to stderr as the program is executed.
 *
 * Invoking `trace()` with zero as an argument turns off opcode tracing.
 *
 * @function module:core#trace
 *
 * @param {number} level
 * The level of tracing to enable.
 *
 * @example
 * trace(1);   // Enables opcode tracing
 * trace(0);   // Disables opcode tracing
 */
static uc_value_t *
uc_trace(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *level = uc_fn_arg(0);
	uint8_t prev_level;

	if (ucv_type(level) != UC_INTEGER) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Invalid level specified");

		return NULL;
	}

	prev_level = vm->trace;
	vm->trace = ucv_int64_get(level);

	return ucv_int64_new(prev_level);
}

/**
 * Get or set the prototype of the array or object value `val`.
 *
 * When invoked without a second argument, the function returns the current
 * prototype of the value in `val` or `null` if there is no prototype or if the
 * given value is neither an object nor an array.
 *
 * When invoked with a second prototype argument, the given `proto` value is set
 * as the prototype on the array or object in `val`.
 *
 * Throws an exception if the given prototype value is not an object.
 *
 * @function module:core#proto
 *
 * @param {Array|Object} val
 * The array or object value.
 *
 * @param {Object} [proto]
 * The optional prototype object.
 *
 * @returns {?Object}
 *
 * @example
 * const arr = [1, 2, 3];
 * proto(arr);                 // Returns the current prototype of the array (null by default)
 * proto(arr, { foo: true });  // Sets the given object as the prototype of the array
 */
static uc_value_t *
uc_proto(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *val = uc_fn_arg(0);
	uc_value_t *proto = NULL;

	if (nargs < 2)
		return ucv_get(ucv_prototype_get(val));

	proto = uc_fn_arg(1);

	if (!ucv_prototype_set(val, proto))
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Passed value is neither a prototype, resource or object");

	ucv_get(proto);

	return ucv_get(val);
}

/**
 * Pause execution for the given amount of milliseconds.
 *
 * @function module:core#sleep
 *
 * @param {number} milliseconds
 * The amount of milliseconds to sleep.
 *
 * @returns {boolean}
 *
 * @example
 * sleep(1000);                          // Sleeps for 1 second
 */
static uc_value_t *
uc_sleep(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *duration = uc_fn_arg(0);
	struct timeval tv;
	int64_t ms;

	ms = ucv_to_integer(duration);

	if (errno != 0 || ms <= 0)
		return ucv_boolean_new(false);

	tv.tv_sec = ms / 1000;
	tv.tv_usec = (ms % 1000) * 1000;

	select(0, NULL, NULL, NULL, &tv);

	return ucv_boolean_new(true);
}

/**
 * Raise an exception with the given message parameter when the value in `cond`
 * is not truish.
 *
 * When `message` is omitted, the default value is `Assertion failed`.
 *
 * @function module:core#assert
 *
 * @param {*} cond
 * The value to check for truthiness.
 *
 * @param {string} [message]
 * The message to include in the exception.
 *
 * @throws {Error} When the condition is falsy.
 *
 * @example
 * assert(true, "This is true");  // No exception is raised
 * assert(false);                 // Exception is raised with the default message "Assertion failed"
 */
static uc_value_t *
uc_assert(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *cond = uc_fn_arg(0);
	uc_value_t *msg = uc_fn_arg(1);
	bool freeable = false;
	char *s;

	if (!ucv_is_truish(cond)) {
		s = msg ? uc_cast_string(vm, &msg, &freeable) : "Assertion failed";

		uc_vm_raise_exception(vm, EXCEPTION_USER, "%s", s);

		if (freeable)
			free(s);

		return NULL;
	}

	return ucv_get(cond);
}

/**
 * Construct a regular expression instance from the given `source` pattern
 * string and any flags optionally specified by the `flags` argument.
 *
 *  - Throws a type error exception if `flags` is not a string or if the string
 *    in `flags` contains unrecognized regular expression flag characters.
 *  - Throws a syntax error when the pattern in `source` cannot be compiled into
 *    a valid regular expression.
 *
 * Returns the compiled regular expression value.
 *
 * @function module:core#regexp
 *
 * @param {string} source
 * The pattern string.
 *
 * @param {string} [flags]
 * The optional regular expression flags.
 *
 * @returns {RegExp}
 *
 * @example
 * regexp('foo.*bar', 'is');   // equivalent to /foo.*bar/is
 * regexp('foo.*bar', 'x');    // throws a "Type error: Unrecognized flag character 'x'" exception
 * regexp('foo.*(');           // throws a "Syntax error: Unmatched ( or \( exception"
 */
static uc_value_t *
uc_regexp(uc_vm_t *vm, size_t nargs)
{
	bool icase = false, newline = false, global = false, freeable;
	uc_value_t *source = uc_fn_arg(0);
	uc_value_t *flags = uc_fn_arg(1);
	uc_value_t *regex = NULL;
	char *p, *err = NULL;

	if (flags) {
		if (ucv_type(flags) != UC_STRING) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Given flags argument is not a string");

			return NULL;
		}

		for (p = ucv_string_get(flags); *p; p++) {
			switch (*p) {
			case 'i':
				icase = true;
				break;

			case 's':
				newline = true;
				break;

			case 'g':
				global = true;
				break;

			default:
				uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Unrecognized flag character '%c'", *p);

				return NULL;
			}
		}
	}

	p = uc_cast_string(vm, &source, &freeable);
	regex = ucv_regexp_new(p, icase, newline, global, &err);

	if (freeable)
		free(p);

	if (err) {
		uc_vm_raise_exception(vm, EXCEPTION_SYNTAX, "%s", err);
		ucv_put(regex);
		free(err);

		return NULL;
	}

	return regex;
}

/**
 * Match the given subject against the supplied wildcard (file glob) pattern.
 *
 *  - If a truthy value is supplied as the third argument, case-insensitive
 *    matching is performed.
 *  - If a non-string value is supplied as the subject, it is converted into a
 *    string before being matched.
 *
 * Returns `true` when the value matched the given pattern, otherwise `false`.
 *
 * @function module:core#wildcard
 *
 * @param {*} subject
 * The subject to match against the wildcard pattern.
 *
 * @param {string} pattern
 * The wildcard pattern.
 *
 * @param {boolean} [nocase]
 * Whether to perform case-insensitive matching.
 *
 * @returns {boolean}
 *
 * @example
 * wildcard("file.txt", "*.txt");        // Returns true
 * wildcard("file.txt", "*.TXT", true);  // Returns true (case-insensitive match)
 * wildcard("file.txt", "*.jpg");        // Returns false
 */
static uc_value_t *
uc_wildcard(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *subject = uc_fn_arg(0);
	uc_value_t *pattern = uc_fn_arg(1);
	uc_value_t *icase = uc_fn_arg(2);
	int flags = 0, rv;
	bool freeable;
	char *s;

	if (!subject || ucv_type(pattern) != UC_STRING)
		return NULL;

	if (ucv_is_truish(icase))
		flags |= FNM_CASEFOLD;

	s = uc_cast_string(vm, &subject, &freeable);
	rv = fnmatch(ucv_string_get(pattern), s, flags);

	if (freeable)
		free(s);

	return ucv_boolean_new(rv == 0);
}

/**
 * Determine the path of the source file currently being executed by ucode.
 *
 * @function module:core#sourcepath
 *
 * @param {number} [depth=0]
 * The depth to walk up the call stack.
 *
 * @param {boolean} [dironly]
 * Whether to return only the directory portion of the source file path.
 *
 * @returns {?string}
 *
 * @example
 * sourcepath();         // Returns the path of the currently executed file
 * sourcepath(1);        // Returns the path of the parent source file
 * sourcepath(2, true);  // Returns the directory portion of the grandparent source file path
 */
static uc_value_t *
uc_sourcepath(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *calldepth = uc_fn_arg(0);
	uc_value_t *dironly = uc_fn_arg(1);
	uc_value_t *rv = NULL;
	uc_callframe_t *frame;
	char *path = NULL;
	int64_t depth;
	size_t i;

	depth = ucv_to_integer(calldepth);

	if (errno)
		depth = 0;

	for (i = vm->callframes.count; i > 0; i--) {
		frame = &vm->callframes.entries[i - 1];

		if (!frame->closure)
			continue;

		if (depth > 0) {
			depth--;
			continue;
		}

		path = realpath(uc_program_function_source(frame->closure->function)->runpath, NULL);
		break;
	}

	if (path) {
		if (ucv_is_truish(dironly))
			rv = ucv_string_new(dirname(path));
		else
			rv = ucv_string_new(path);

		free(path);
	}

	return rv;
}

static uc_value_t *
uc_min_max(uc_vm_t *vm, size_t nargs, int cmp)
{
	uc_value_t *rv = NULL, *val;
	bool set = false;
	size_t i;

	for (i = 0; i < nargs; i++) {
		val = uc_fn_arg(i);

		if (!set || ucv_compare(cmp, val, rv, NULL)) {
			set = true;
			rv = val;
		}
	}

	return ucv_get(rv);
}

/**
 * Return the smallest value among all parameters passed to the function.
 *
 * @function module:core#min
 *
 * @param {...*} [val]
 * The values to compare.
 *
 * @returns {*}
 *
 * @example
 * min(5, 2.1, 3, "abc", 0.3);            // Returns 0.3
 * min(1, "abc");                         // Returns 1
 * min("1", "abc");                       // Returns "1"
 * min("def", "abc", "ghi");              // Returns "abc"
 * min(true, false);                      // Returns false
 */
static uc_value_t *
uc_min(uc_vm_t *vm, size_t nargs)
{
	return uc_min_max(vm, nargs, I_LT);
}

/**
 * Return the largest value among all parameters passed to the function.
 *
 * @function module:core#max
 *
 * @param {...*} [val]
 * The values to compare.
 *
 * @returns {*}
 *
 * @example
 * max(5, 2.1, 3, "abc", 0.3);            // Returns 5
 * max(1, "abc");                         // Returns 1 (!)
 * max("1", "abc");                       // Returns "abc"
 * max("def", "abc", "ghi");              // Returns "ghi"
 * max(true, false);                      // Returns true
 */
static uc_value_t *
uc_max(uc_vm_t *vm, size_t nargs)
{
	return uc_min_max(vm, nargs, I_GT);
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

/**
 * Decodes the given base64 encoded string and returns the decoded result.
 *
 *  - If non-whitespace, non-base64 characters are encountered, if invalid
 *    padding or trailing garbage is found, the function returns `null`.
 *  - If a non-string argument is given, the function returns `null`.
 *
 * @function module:core#b64dec
 *
 * @param {string} str
 * The base64 encoded string to decode.
 *
 * @returns {?string}
 *
 * @example
 * b64dec("VGhpcyBpcyBhIHRlc3Q=");         // Returns "This is a test"
 * b64dec(123);                           // Returns null
 * b64dec("XXX");                         // Returns null
 */
static uc_value_t *
uc_b64dec(uc_vm_t *vm, size_t nargs)
{
	enum { BYTE1, BYTE2, BYTE3, BYTE4 } state;
	uc_value_t *str = uc_fn_arg(0);
	uc_stringbuf_t *buf;
	const char *src;
	unsigned int ch;
	uint8_t val;
	size_t off;

	if (ucv_type(str) != UC_STRING)
		return NULL;

	buf = ucv_stringbuf_new();
	src = ucv_string_get(str);
	off = printbuf_length(buf);

	state = BYTE1;

	/* memset the last expected output char to pre-grow the output buffer */
	printbuf_memset(buf, off + (ucv_string_length(str) / 4) * 3, 0, 1);

	while ((ch = (unsigned char)*src++) != '\0') {
		if (isspace(ch))	/* Skip whitespace anywhere. */
			continue;

		if (ch == '=')
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
			goto err;

		switch (state) {
		case BYTE1:
			buf->buf[off] = val << 2;
			state = BYTE2;
			break;

		case BYTE2:
			buf->buf[off++] |= val >> 4;
			buf->buf[off] = (val & 0x0f) << 4;
			state = BYTE3;
			break;

		case BYTE3:
			buf->buf[off++] |= val >> 2;
			buf->buf[off] = (val & 0x03) << 6;
			state = BYTE4;
			break;

		case BYTE4:
			buf->buf[off++] |= val;
			state = BYTE1;
			break;
		}
	}

	/*
	 * We are done decoding Base-64 chars.  Let's see if we ended
	 * on a byte boundary, and/or with erroneous trailing characters.
	 */

	if (ch == '=') {			/* We got a pad char. */
		ch = (unsigned char)*src++;	/* Skip it, get next. */
		switch (state) {
		case BYTE1:		/* Invalid = in first position */
		case BYTE2:		/* Invalid = in second position */
			goto err;

		case BYTE3:		/* Valid, means one byte of info */
			/* Skip any number of spaces. */
			for (; ch != '\0'; ch = (unsigned char)*src++)
				if (!isspace(ch))
					break;
			/* Make sure there is another trailing = sign. */
			if (ch != '=')
				goto err;
			ch = (unsigned char)*src++;		/* Skip the = */
			/* Fall through to "single trailing =" case. */
			/* FALLTHROUGH */

		case BYTE4:		/* Valid, means two bytes of info */
			/*
			 * We know this char is an =.  Is there anything but
			 * whitespace after it?
			 */
			for (; ch != '\0'; ch = (unsigned char)*src++)
				if (!isspace(ch))
					goto err;

			/*
			 * Now make sure for cases BYTE3 and BYTE4 that the "extra"
			 * bits that slopped past the last full byte were
			 * zeros.  If we don't check them, they become a
			 * subliminal channel.
			 */
			if (buf->buf[off] != 0)
				goto err;
		}
	} else {
		/*
		 * We ended by seeing the end of the string.  Make sure we
		 * have no partial bytes lying around.
		 */
		if (state != BYTE1)
			goto err;
	}

	/* Truncate buffer length to actual output length */
	buf->bpos = off;

	return ucv_stringbuf_finish(buf);

err:
	printbuf_free(buf);

	return NULL;
}

static const char Base64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Encodes the given string into base64 and returns the resulting string.
 *
 *  - If a non-string argument is given, the function returns `null`.
 *
 * @function module:core#b64enc
 *
 * @param {string} str
 * The string to encode.
 *
 * @returns {?string}
 *
 * @example
 * b64enc("This is a test");  // Returns "VGhpcyBpcyBhIHRlc3Q="
 * b64enc(123);               // Returns null
 */
static uc_value_t *
uc_b64enc(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *str = uc_fn_arg(0);
	unsigned char input[3] = {0};
	uc_stringbuf_t *buf;
	const char *src;
	char output[4];
	size_t len, i;

	if (ucv_type(str) != UC_STRING)
		return NULL;

	buf = ucv_stringbuf_new();
	src = ucv_string_get(str);
	len = ucv_string_length(str);

	while (2 < len) {
		input[0] = (unsigned char)*src++;
		input[1] = (unsigned char)*src++;
		input[2] = (unsigned char)*src++;
		len -= 3;

		output[0] = Base64[input[0] >> 2];
		output[1] = Base64[((input[0] & 0x03) << 4) + (input[1] >> 4)];
		output[2] = Base64[((input[1] & 0x0f) << 2) + (input[2] >> 6)];
		output[3] = Base64[input[2] & 0x3f];

		ucv_stringbuf_addstr(buf, output, sizeof(output));
	}

	/* Now we worry about padding. */
	if (0 != len) {
		/* Get what's left. */
		input[0] = input[1] = input[2] = '\0';
		for (i = 0; i < len; i++)
			input[i] = *src++;

		output[0] = Base64[input[0] >> 2];
		output[1] = Base64[((input[0] & 0x03) << 4) + (input[1] >> 4)];
		output[2] = (len == 1) ? '=' : Base64[((input[1] & 0x0f) << 2) + (input[2] >> 6)];
		output[3] = '=';

		ucv_stringbuf_addstr(buf, output, sizeof(output));
	}

	return ucv_stringbuf_finish(buf);
}

/* End of base64 code.
 * -------------------------------------------------------------------------
 */

static unsigned long
uc_uniq_ucv_hash(const void *k)
{
	union { double d; int64_t i; uint64_t u; } conv;
	uc_value_t *uv = (uc_value_t *)k;
	unsigned int h;
	uint8_t *u8;
	size_t len;

	h = ucv_type(uv);

	switch (h) {
	case UC_STRING:
		u8 = (uint8_t *)ucv_string_get(uv);
		len = ucv_string_length(uv);
		break;

	case UC_INTEGER:
		conv.i = ucv_int64_get(uv);

		if (errno == ERANGE) {
			h *= 2;
			conv.u = ucv_uint64_get(uv);
		}

		u8 = (uint8_t *)&conv.u;
		len = sizeof(conv.u);
		break;

	case UC_DOUBLE:
		conv.d = ucv_double_get(uv);

		u8 = (uint8_t *)&conv.u;
		len = sizeof(conv.u);
		break;

	default:
		u8 = (uint8_t *)&uv;
		len = sizeof(uv);
		break;
	}

	while (len > 0) {
		h = h * 129 + (*u8++) + LH_PRIME;
		len--;
	}

	return h;
}

static int
uc_uniq_ucv_equal(const void *k1, const void *k2)
{
	uc_value_t *uv1 = (uc_value_t *)k1;
	uc_value_t *uv2 = (uc_value_t *)k2;

	if (!ucv_is_scalar(uv1) && !ucv_is_scalar(uv2))
		return (uv1 == uv2);

	/* for the sake of array item uniqueness, treat two NaNs as equal */
	if (ucv_type(uv1) == UC_DOUBLE && ucv_type(uv2) == UC_DOUBLE &&
	    isnan(ucv_double_get(uv1)) && isnan(ucv_double_get(uv2)))
	    return true;

	return ucv_is_equal(uv1, uv2);
}

/**
 * Returns a new array containing all unique values of the given input array.
 *
 *  - The order is preserved, and subsequent duplicate values are skipped.
 *  - If a non-array argument is given, the function returns `null`.
 *
 * @function module:core#uniq
 *
 * @param {Array} array
 * The input array.
 *
 * @returns {?Array}
 *
 * @example
 * uniq([1, true, "foo", 2, true, "bar", "foo"]);       // Returns [1, true, "foo", 2, "bar"]
 * uniq("test");                                        // Returns null
 */
static uc_value_t *
uc_uniq(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *list = uc_fn_arg(0);
	uc_value_t *uniq = NULL;
	struct lh_table *seen;
	unsigned long hash;
	uc_value_t *item;
	size_t i, len;

	if (ucv_type(list) != UC_ARRAY)
		return NULL;

	seen = lh_table_new(16, NULL, uc_uniq_ucv_hash, uc_uniq_ucv_equal);
	uniq = ucv_array_new(vm);

	assert(seen && uniq);

	for (i = 0, len = ucv_array_length(list); i < len; i++) {
		item = ucv_array_get(list, i);
		hash = lh_get_hash(seen, item);

		if (!lh_table_lookup_entry_w_hash(seen, item, hash)) {
			lh_table_insert_w_hash(seen, item, NULL, hash, 0);
			ucv_array_push(uniq, ucv_get(item));
		}
	}

	lh_table_free(seen);

	return uniq;
}

/**
 * A time spec is a plain object describing a point in time, it is returned by
 * the {@link module:core#gmtime|gmtime()} and
 * {@link module:core#localtime|localtime()} functions and expected as parameter
 * by the complementary {@link module:core#timegm|timegm()} and
 * {@link module:core#timelocal|timelocal()} functions.
 *
 * When returned by `gmtime()` or `localtime()`, all members of the object will
 * be initialized, when passed as argument to `timegm()` or `timelocal()`, most
 * member values are optional.
 *
 * @typedef {Object} module:core.TimeSpec
 * @property {number} sec - Seconds (0..60)
 * @property {number} min - Minutes (0..59)
 * @property {number} hour - Hours (0..23)
 * @property {number} mday - Day of month (1..31)
 * @property {number} mon - Month (1..12)
 * @property {number} year - Year (>= 1900)
 * @property {number} wday - Day of week (1..7, Sunday = 7)
 * @property {number} yday - Day of year (1-366, Jan 1st = 1)
 * @property {number} isdst - Daylight saving time in effect (yes = 1)
 */
static uc_value_t *
uc_gettime_common(uc_vm_t *vm, size_t nargs, bool local)
{
	uc_value_t *ts = uc_fn_arg(0), *res;
	time_t t = ts ? (time_t)ucv_to_integer(ts) : time(NULL);
	struct tm *tm = (local ? localtime : gmtime)(&t);

	if (!tm)
		return NULL;

	res = ucv_object_new(vm);

	ucv_object_add(res, "sec", ucv_int64_new(tm->tm_sec));
	ucv_object_add(res, "min", ucv_int64_new(tm->tm_min));
	ucv_object_add(res, "hour", ucv_int64_new(tm->tm_hour));
	ucv_object_add(res, "mday", ucv_int64_new(tm->tm_mday));
	ucv_object_add(res, "mon", ucv_int64_new(tm->tm_mon + 1));
	ucv_object_add(res, "year", ucv_int64_new(tm->tm_year + 1900));
	ucv_object_add(res, "wday", ucv_int64_new(tm->tm_wday ? tm->tm_wday : 7));
	ucv_object_add(res, "yday", ucv_int64_new(tm->tm_yday + 1));
	ucv_object_add(res, "isdst", ucv_int64_new(tm->tm_isdst));

	return res;
}

/**
 * Return the given epoch timestamp (or now, if omitted) as a dictionary
 * containing broken-down date and time information according to the local
 * system timezone.
 *
 * See {@link module:core.TimeSpec|TimeSpec} for a description of the fields.
 *
 * Note that in contrast to the underlying `localtime(3)` C library function,
 * the values for `mon`, `wday`, and `yday` are 1-based, and the `year` is
 * 1900-based.
 *
 * @function module:core#localtime
 *
 * @param {number} [epoch]
 * The epoch timestamp.
 *
 * @returns {module:core.TimeSpec}
 *
 * @example
 * localtime(1647953502);
 * // Returns:
 * // {
 * //     sec: 42,
 * //     min: 51,
 * //     hour: 13,
 * //     mday: 22,
 * //     mon: 3,
 * //     year: 2022,
 * //     wday: 2,
 * //     yday: 81,
 * //     isdst: 0
 * // }
 */
static uc_value_t *
uc_localtime(uc_vm_t *vm, size_t nargs)
{
	return uc_gettime_common(vm, nargs, true);
}

/**
 * Like `localtime()` but interpreting the given epoch value as UTC time.
 *
 * See {@link module:core#localtime|localtime()} for details on the return value.
 *
 * @function module:core#gmtime
 *
 * @param {number} [epoch]
 * The epoch timestamp.
 *
 * @returns {module:core.TimeSpec}
 *
 * @example
 * gmtime(1647953502);
 * // Returns:
 * // {
 * //     sec: 42,
 * //     min: 51,
 * //     hour: 13,
 * //     mday: 22,
 * //     mon: 3,
 * //     year: 2022,
 * //     wday: 2,
 * //     yday: 81,
 * //     isdst: 0
 * // }
 */
static uc_value_t *
uc_gmtime(uc_vm_t *vm, size_t nargs)
{
	return uc_gettime_common(vm, nargs, false);
}

static uc_value_t *
uc_mktime_common(uc_vm_t *vm, size_t nargs, bool local)
{
#define FIELD(name, required) \
	{ #name, required, offsetof(struct tm, tm_##name) }

	const struct {
		const char *name;
		bool required;
		size_t off;
	} fields[] = {
		FIELD(sec, false),
		FIELD(min, false),
		FIELD(hour, false),
		FIELD(mday, true),
		FIELD(mon, true),
		FIELD(year, true),
		FIELD(isdst, false)
	};

	uc_value_t *to = uc_fn_arg(0), *v;
	struct tm tm = { 0 };
	bool exists;
	time_t t;
	size_t i;

	if (ucv_type(to) != UC_OBJECT)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(fields); i++) {
		v = ucv_object_get(to, fields[i].name, &exists);

		if (!exists && fields[i].required)
			return NULL;

		*(int *)((char *)&tm + fields[i].off) = (int)ucv_to_integer(v);
	}

	if (tm.tm_mon > 0)
		tm.tm_mon--;

	if (tm.tm_year >= 1900)
		tm.tm_year -= 1900;

	t = (local ? mktime : timegm)(&tm);

	return (t != (time_t)-1) ? ucv_int64_new((int64_t)t) : NULL;
}

/**
 * Performs the inverse operation of {@link module:core#localtime|localtime()}
 * by taking a broken-down date and time dictionary and transforming it into an
 * epoch value according to the local system timezone.
 *
 * The `wday` and `yday` fields of the given date time specification are
 * ignored. Field values outside of their valid range are internally normalized,
 * e.g. October 40th is interpreted as November 9th.
 *
 * Returns the resulting epoch value or null if the input date time dictionary
 * was invalid or if the date time specification cannot be represented as epoch
 * value.
 *
 * @function module:core#timelocal
 *
 * @param {module:core.TimeSpec} datetimespec
 * The broken-down date and time dictionary.
 *
 * @returns {?number}
 *
 * @example
 * timelocal({ "sec": 42, "min": 51, "hour": 13, "mday": 22, "mon": 3, "year": 2022, "isdst": 0 });
 * // Returns 1647953502
 */
static uc_value_t *
uc_timelocal(uc_vm_t *vm, size_t nargs)
{
	return uc_mktime_common(vm, nargs, true);
}

/**
 * Like `timelocal()` but interpreting the given date time specification as UTC
 * time.
 *
 * See {@link module:core#timelocal|timelocal()} for details.
 *
 * @function module:core#timegm
 *
 * @param {module:core.TimeSpec} datetimespec
 * The broken-down date and time dictionary.
 *
 * @returns {?number}
 *
 * @example
 * timegm({ "sec": 42, "min": 51, "hour": 13, "mday": 22, "mon": 3, "year": 2022, "isdst": 0 });
 * // Returns 1647953502
 */
static uc_value_t *
uc_timegm(uc_vm_t *vm, size_t nargs)
{
	return uc_mktime_common(vm, nargs, false);
}

/**
 * Reads the current second and microsecond value of the system clock.
 *
 * By default, the realtime clock is queried which might skew forwards or
 * backwards due to NTP changes, system sleep modes etc. If a truish value is
 * passed as argument, the monotonic system clock is queried instead, which will
 * return the monotonically increasing time since some arbitrary point in the
 * past (usually the system boot time).
 *
 * Returns a two element array containing the full seconds as the first element
 * and the nanosecond fraction as the second element.
 *
 * Returns `null` if a monotonic clock value is requested and the system does
 * not implement this clock type.
 *
 * @function module:core#clock
 *
 * @param {boolean} [monotonic]
 * Whether to query the monotonic system clock.
 *
 * @returns {?number[]}
 *
 * @example
 * clock();        // [ 1647954926, 798269464 ]
 * clock(true);    // [ 474751, 527959975 ]
 */
static uc_value_t *
uc_clock(uc_vm_t *vm, size_t nargs)
{
	clockid_t id = ucv_is_truish(uc_fn_arg(0)) ? CLOCK_MONOTONIC : CLOCK_REALTIME;
	struct timespec ts;
	uc_value_t *res;

	if (clock_gettime(id, &ts) == -1)
		return NULL;

	res = ucv_array_new(vm);

	ucv_array_set(res, 0, ucv_int64_new((int64_t)ts.tv_sec));
	ucv_array_set(res, 1, ucv_int64_new((int64_t)ts.tv_nsec));

	return res;
}

/**
 * Encodes the given byte string into a hexadecimal digit string, converting
 * the input value to a string if needed.
 *
 * @function module:core#hexenc
 *
 * @param {string} val
 * The byte string to encode.
 *
 * @returns {string}
 *
 * @example
 * hexenc("Hello world!\n");   // "48656c6c6f20776f726c64210a"
 */
static uc_value_t *
uc_hexenc(uc_vm_t *vm, size_t nargs)
{
	const char *hex = "0123456789abcdef";
	uc_value_t *input = uc_fn_arg(0);
	uc_stringbuf_t *buf;
	size_t off, len;
	uint8_t byte;

	if (!input)
		return NULL;

	buf = ucv_stringbuf_new();
	off = printbuf_length(buf);

	ucv_to_stringbuf(vm, buf, input, false);

	len = printbuf_length(buf) - off;

	/* memset the last expected output char to grow the output buffer */
	printbuf_memset(buf, off + len * 2, 0, 1);

	/* translate string into hex back to front to reuse the same buffer */
	while (len > 0) {
		byte = buf->buf[--len + off];
		buf->buf[off + len * 2 + 0] = hex[byte / 16];
		buf->buf[off + len * 2 + 1] = hex[byte % 16];
	}

	/* do not include sentinel `\0` in string length */
	buf->bpos--;

	return ucv_stringbuf_finish(buf);
}

static inline uint8_t
hexval(unsigned char c, bool lo)
{
	return ((c > '9') ? (c - 'a') + 10 : c - '0') << (lo ? 0 : 4);
}

/**
 * Decodes the given hexadecimal digit string into a byte string, optionally
 * skipping specified characters.
 *
 * If the characters to skip are not specified, a default of `" \t\n"` is used.
 *
 * Returns null if the input string contains invalid characters or an uneven
 * amount of hex digits.
 *
 * Returns the decoded byte string on success.
 *
 * @function module:core#hexdec
 *
 * @param {string} hexstring
 * The hexadecimal digit string to decode.
 *
 * @param {string} [skipchars]
 * The characters to skip during decoding.
 *
 * @returns {?string}
 *
 * @example
 * hexdec("48656c6c6f20776f726c64210a");  // "Hello world!\n"
 * hexdec("44:55:66:77:33:44", ":");      // "DUfw3D"
 */
static uc_value_t *
uc_hexdec(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *input = uc_fn_arg(0);
	uc_value_t *skip = uc_fn_arg(1);
	size_t len, off, n, i;
	uc_stringbuf_t *buf;
	unsigned char *p;
	const char *s;

	if (ucv_type(input) != UC_STRING)
		return NULL;

	if (skip && ucv_type(skip) != UC_STRING)
		return NULL;

	p = (unsigned char *)ucv_string_get(input);
	len = ucv_string_length(input);

	s = skip ? (const char *)ucv_string_get(skip) : " \t\n";

	for (i = 0, n = 0; i < len; i++) {
		if (isxdigit(p[i]))
			n++;
		else if (!s || !strchr(s, p[i]))
			return NULL;
	}

	if (n & 1)
		return NULL;

	buf = ucv_stringbuf_new();
	off = printbuf_length(buf);

	/* preallocate the output buffer */
	printbuf_memset(buf, off, 0, n / 2 + 1);

	for (i = 0, n = 0; i < len; i++) {
		if (!isxdigit(p[i]))
			continue;

		buf->buf[off + (n >> 1)] |= hexval(p[i] | 32, n & 1);
		n++;
	}

	/* do not include sentinel `\0` in string length */
	buf->bpos--;

	return ucv_stringbuf_finish(buf);
}

/**
 * Interacts with the mark and sweep garbage collector of the running ucode
 * virtual machine.
 *
 * Depending on the given `operation` string argument, the meaning of `argument`
 * and the function return value differs.
 *
 * The following operations are defined:
 *
 * - `collect` - Perform a complete garbage collection cycle, returns `true`.
 * - `start` - (Re-)start periodic garbage collection, `argument` is an optional
 *             integer in the range `1..65535` specifying the interval.
 *             Defaults to `1000` if omitted. Returns `true` if the periodic GC
 *             was previously stopped and is now started or if the interval
 *             changed. Returns `false` otherwise.
 * - `stop` - Stop periodic garbage collection. Returns `true` if the periodic
 *            GC was previously started and is now stopped, `false` otherwise.
 * - `count` - Count the amount of active complex object references in the VM
 *             context, returns the counted amount.
 *
 * If the `operation` argument is omitted, the default is `collect`.
 *
 * @function module:core#gc
 *
 * @param {string} [operation]
 * The operation to perform.
 *
 * @param {*} [argument]
 * The argument for the operation.
 *
 * @returns {?(boolean|number)}
 *
 * @example
 * gc();         // true
 * gc("start");  // true
 * gc("count");  // 42
 */
static uc_value_t *
uc_gc(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *operation = uc_fn_arg(0);
	uc_value_t *argument = uc_fn_arg(1);
	const char *op = NULL;
	uc_weakref_t *ref;
	int64_t n;

	if (operation != NULL && ucv_type(operation) != UC_STRING)
		return NULL;

	op = ucv_string_get(operation);

	if (!op || !strcmp(op, "collect")) {
		ucv_gc(vm);

		return ucv_boolean_new(true);
	}
	else if (!strcmp(op, "start")) {
		n = argument ? ucv_int64_get(argument) : 0;

		if (errno || n < 0 || n > 0xFFFF)
			return NULL;

		if (n == 0)
			n = GC_DEFAULT_INTERVAL;

		return ucv_boolean_new(uc_vm_gc_start(vm, n));
	}
	else if (!strcmp(op, "stop")) {
		return ucv_boolean_new(uc_vm_gc_stop(vm));
	}
	else if (!strcmp(op, "count")) {
		for (n = 0, ref = vm->values.next; ref != &vm->values; ref = ref->next)
			n++;

		return ucv_uint64_new(n);
	}

	return NULL;
}

/**
 * A parse configuration is a plain object describing options to use when
 * compiling ucode at runtime. It is expected as parameter by the
 * {@link module:core#loadfile|loadfile()} and
 * {@link module:core#loadstring|loadstring()} functions.
 *
 * All members of the parse configuration object are optional and will default
 * to the state of the running ucode file if omitted.
 *
 * @typedef {Object} module:core.ParseConfig
 *
 * @property {boolean} lstrip_blocks
 * Whether to strip whitespace preceding template directives.
 * See {@link tutorial-02-syntax.html#whitespace-handling|Whitespace handling}.
 *
 * @property {boolean} trim_blocks
 * Whether to trim trailing newlines following template directives.
 * See {@link tutorial-02-syntax.html#whitespace-handling|Whitespace handling}.
 *
 * @property {boolean} strict_declarations
 * Whether to compile the code in strict mode (`true`) or not (`false`).
 *
 * @property {boolean} raw_mode
 * Whether to compile the code in plain script mode (`true`) or not (`false`).
 *
 * @property {string[]} module_search_path
 * Override the module search path for compile time imports while compiling the
 * ucode source.
 *
 * @property {string[]} force_dynlink_list
 * List of module names assumed to be dynamic library extensions, allows
 * compiling ucode source with import statements referring to `*.so` extensions
 * not present at compile time.
 */
static void
uc_compile_parse_config(uc_parse_config_t *config, uc_value_t *spec)
{
	uc_value_t *v, *p;
	size_t i, j;
	bool found;

	struct {
		const char *key;
		bool *flag;
		uc_search_path_t *path;
	} fields[] = {
		{ "lstrip_blocks",       &config->lstrip_blocks,       NULL },
		{ "trim_blocks",         &config->trim_blocks,         NULL },
		{ "strict_declarations", &config->strict_declarations, NULL },
		{ "raw_mode",            &config->raw_mode,            NULL },
		{ "module_search_path",  NULL, &config->module_search_path  },
		{ "force_dynlink_list",  NULL, &config->force_dynlink_list  }
	};

	for (i = 0; i < ARRAY_SIZE(fields); i++) {
		v = ucv_object_get(spec, fields[i].key, &found);

		if (!found)
			continue;

		if (fields[i].flag) {
			*fields[i].flag = ucv_is_truish(v);
		}
		else if (fields[i].path) {
			fields[i].path->count = 0;
			fields[i].path->entries = NULL;

			for (j = 0; j < ucv_array_length(v); j++) {
				p = ucv_array_get(v, j);

				if (ucv_type(p) != UC_STRING)
					continue;

				uc_vector_push(fields[i].path, ucv_string_get(p));
			}
		}
	}
}

static uc_value_t *
uc_load_common(uc_vm_t *vm, size_t nargs, uc_source_t *source)
{
	uc_parse_config_t conf = *vm->config;
	uc_program_t *program;
	uc_value_t *closure;
	char *err = NULL;

	uc_compile_parse_config(&conf, uc_fn_arg(1));

	program = uc_compile(&conf, source, &err);
	closure = program ? ucv_closure_new(vm, uc_program_entry(program), false) : NULL;

	uc_program_put(program);

	if (!vm->config || conf.module_search_path.entries != vm->config->module_search_path.entries)
		uc_vector_clear(&conf.module_search_path);

	if (!vm->config || conf.force_dynlink_list.entries != vm->config->force_dynlink_list.entries)
		uc_vector_clear(&conf.force_dynlink_list);

	if (!closure) {
		uc_error_message_indent(&err);

		if (source->buffer)
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
				"Unable to compile source string:\n\n%s", err);
		else
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
				"Unable to compile source file '%s':\n\n%s", source->filename, err);
	}

	uc_source_put(source);
	free(err);

	return closure;
}

/**
 * Compiles the given code string into a ucode program and returns the resulting
 * program entry function.
 *
 * The optional `options` dictionary overrides parse and compile options.
 *
 *  - If a non-string `code` argument is given, it is implicitly converted to a
 *    string value first.
 *  - If `options` is omitted or a non-object value, the compile options of the
 *    running ucode program are reused.
 *
 * See {@link module:core.ParseConfig|ParseConfig} for known keys within the
 * `options` object. Unrecognized keys are ignored, unspecified options default
 * to those of the running program.
 *
 * Returns the compiled program entry function.
 *
 * Throws an exception on compilation errors.
 *
 * @function module:core#loadstring
 *
 * @param {string} code
 * The code string to compile.
 *
 * @param {module:core.ParseConfig} [options]
 * The options for compilation.
 *
 * @returns {Function}
 *
 * @example
 * let fn1 = loadstring("Hello, {{ name }}", { raw_mode: false });
 *
 * global.name = "Alice";
 * fn1(); // prints `Hello, Alice`
 *
 *
 * let fn2 = loadstring("return 1 + 2;", { raw_mode: true });
 * fn2(); // 3
 */
static uc_value_t *
uc_loadstring(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *code = uc_fn_arg(0);
	uc_source_t *source;
	size_t len;
	char *s;

	if (ucv_type(code) == UC_STRING) {
		len = ucv_string_length(code);
		s = xalloc(len);
		memcpy(s, ucv_string_get(code), len);
	}
	else {
		s = ucv_to_string(vm, code);
		len = strlen(s);
	}

	source = uc_source_new_buffer("[loadstring argument]", s, len);

	if (!source) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			"Unable to allocate source buffer: %s",
			strerror(errno));

		return NULL;
	}

	return uc_load_common(vm, nargs, source);
}

/**
 * Compiles the given file into a ucode program and returns the resulting
 * program entry function.
 *
 * See {@link module:core#loadstring|`loadstring()`} for details.
 *
 * Returns the compiled program entry function.
 *
 * Throws an exception on compilation or file I/O errors.
 *
 * @function module:core#loadfile
 *
 * @param {string} path
 * The path of the file to compile.
 *
 * @param {module:core.ParseConfig} [options]
 * The options for compilation.
 *
 * @returns {Function}
 *
 * @example
 * loadfile("./templates/example.uc");  // function main() { ... }
 */
static uc_value_t *
uc_loadfile(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path = uc_fn_arg(0);
	uc_source_t *source;

	if (ucv_type(path) != UC_STRING)
		return NULL;

	source = uc_source_new_file(ucv_string_get(path));

	if (!source) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			"Unable to open source file %s: %s",
			ucv_string_get(path), strerror(errno));

		return NULL;
	}

	return uc_load_common(vm, nargs, source);
}

/**
 * Calls the given function value with a modified environment.
 *
 * The given `ctx` argument is used as `this` context for the invoked function
 * and the given `scope` value as global environment. Any further arguments are
 * passed to the invoked function as-is.
 *
 * When `ctx` is omitted or `null`, the function will get invoked with `this`
 * being `null`.
 *
 * When `scope` is omitted or `null`, the function will get executed with the
 * current global environment of the running program. When `scope` is set to a
 * dictionary, the dictionary is used as global function environment.
 *
 * When the `scope` dictionary has no prototype, the current global environment
 * will be set as prototype, means the scope will inherit from it.
 *
 * When a scope prototype is set, it is kept. This allows passing an isolated
 * (sandboxed) function scope without access to the global environment.
 *
 * Any further argument is forwarded as-is to the invoked function as function
 * call argument.
 *
 * Returns `null` if the given function value `fn` is not callable.
 *
 * Returns the return value of the invoked function in all other cases.
 *
 * Forwards exceptions thrown by the invoked function.
 *
 * @function module:core#call
 *
 * @param {Function} fn
 * Function value to call.
 *
 * @param {*} [ctx=null]
 * `this` context for the invoked function.
 *
 * @param {Object} [scope=null]
 * Global environment for the invoked function.
 *
 * @param {...*} [arg]
 * Additional arguments to pass to the invoked function.
 *
 * @returns {*}
 *
 * @example
 * // Override this context
 * call(function() { printf("%J\n", this) });            // null
 * call(function() { printf("%J\n", this) }, null);      // null
 * call(function() { printf("%J\n", this) }, { x: 1 });  // { "x": 1 }
 * call(function() { printf("%J\n", this) }, { x: 2 });  // { "x": 2 }
 *
 * // Run with default scope
 * global.a = 1;
 * call(function() { printf("%J\n", a) });                  // 1
 *
 * // Override scope, inherit from current global scope (implicit)
 * call(function() { printf("%J\n", a) }, null, { a: 2 });  // 2
 *
 * // Override scope, inherit from current global scope (explicit)
 * call(function() { printf("%J\n", a) }, null,
 *         proto({ a: 2 }, global));                        // 2
 *
 * // Override scope, don't inherit (pass `printf()` but not `a`)
 * call(function() { printf("%J\n", a) }, null,
 *         proto({}, { printf }));                          // null
 *
 * // Forward arguments
 * x = call((x, y, z) => x * y * z, null, null, 2, 3, 4);   // x = 24
 */
static uc_value_t *
uc_callfunc(uc_vm_t *vm, size_t nargs)
{
	size_t argoff = vm->stack.count - nargs, i;
	uc_value_t *fn_scope, *prev_scope, *res;
	uc_value_t *fn = uc_fn_arg(0);
	uc_value_t *this = uc_fn_arg(1);
	uc_value_t *scope = uc_fn_arg(2);

	if (!ucv_is_callable(fn))
		return NULL;

	if (scope && ucv_type(scope) != UC_OBJECT)
		return NULL;

	if (ucv_prototype_get(scope)) {
		fn_scope = ucv_get(scope);
	}
	else if (scope) {
		fn_scope = ucv_object_new(vm);

		ucv_object_foreach(scope, k, v)
			ucv_object_add(fn_scope, k, ucv_get(v));

		ucv_prototype_set(fn_scope, ucv_get(uc_vm_scope_get(vm)));
	}
	else {
		fn_scope = NULL;
	}

	uc_vm_stack_push(vm, ucv_get(this));
	uc_vm_stack_push(vm, ucv_get(fn));

	for (i = 3; i < nargs; i++)
		uc_vm_stack_push(vm, ucv_get(vm->stack.entries[3 + argoff++]));

	if (fn_scope) {
		prev_scope = ucv_get(uc_vm_scope_get(vm));
		uc_vm_scope_set(vm, fn_scope);
	}

	if (uc_vm_call(vm, true, i - 3) == EXCEPTION_NONE)
		res = uc_vm_stack_pop(vm);
	else
		res = NULL;

	if (fn_scope)
		uc_vm_scope_set(vm, prev_scope);

	return res;
}

/**
 * Set or query process signal handler function.
 *
 * When invoked with two arguments, a signal specification and a signal handler
 * value, this function configures a new process signal handler.
 *
 * When invoked with one argument, a signal specification, this function returns
 * the currently configured handler for the given signal.
 *
 * The signal specification might either be an integer signal number or a string
 * value containing a signal name (with or without "SIG" prefix). Signal names
 * are treated case-insensitively.
 *
 * The signal handler might be either a callable function value or one of the
 * two special string values `"ignore"` and `"default"`. Passing `"ignore"` will
 * mask the given process signal while `"default"` will restore the operating
 * systems default behaviour for the given signal.
 *
 * In case a callable handler function is provided, it is invoked at the
 * earliest  opportunity after receiving the corresponding signal from the
 * operating system. The invoked function will receive a single argument, the
 * number of the signal it is invoked for.
 *
 * Note that within the ucode VM, process signals are not immediately delivered,
 * instead the VM keeps track of received signals and delivers them to the ucode
 * script environment at the next opportunity, usually before executing the next
 * byte code instruction. This means that if a signal is received while
 * performing a computationally expensive operation in C mode, such as a complex
 * regexp match, the corresponding ucode signal handler will only be invoked
 * after that operation concluded and control flow returns to the VM.
 *
 * Returns the signal handler function or one of the special values `"ignore"`
 * or `"default"` corresponding to the given signal specification.
 *
 * Returns `null` if an invalid signal spec or signal handler was provided.
 *
 * Returns `null` if changing the signal action failed, e.g. due to insufficient
 * permission, or when attempting to ignore a non-ignorable signal.
 *
 * @function module:core#signal
 *
 * @param {number|string} signal
 * The signal to query/set handler for.
 *
 * @param {Function|string} [handler]
 * The signal handler to install for the given signal.
 *
 * @returns {Function|string}
 *
 * @example
 * // Ignore signals
 * signal('INT', 'ignore');      // "ignore"
 * signal('SIGINT', 'ignore');   // "ignore" (equivalent to 'INT')
 * signal('sigterm', 'ignore');  // "ignore" (signal names are case insensitive)
 * signal(9, 'ignore');          // null (SIGKILL cannot be ignored)
 *
 * // Restore signal default behavior
 * signal('INT', 'default');     // "default"
 * signal('foobar', 'default');  // null (unknown signal name)
 * signal(-313, 'default');      // null (invalid signal number)
 *
 * // Set custom handler function
 * function intexit(signo) {
 *   printf("I received signal number %d\n", signo);
 *   exit(1);
 * }
 *
 * signal('SIGINT', intexit);    // returns intexit
 * signal('SIGINT') == intexit;  // true
 */
static uc_value_t *
uc_signal(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *signame = uc_fn_arg(0);
	uc_value_t *sighandler = uc_fn_arg(1);
	struct sigaction sa = { 0 };
	char *sigstr;
	int sig;

	if (ucv_type(signame) == UC_INTEGER) {
		sig = (int)ucv_int64_get(signame);

		if (errno || sig < 0 || sig >= UC_SYSTEM_SIGNAL_COUNT)
			return NULL;

		if (!uc_system_signal_names[sig])
			return NULL;
	}
	else if (ucv_type(signame) == UC_STRING) {
		sigstr = ucv_string_get(signame);

		if (!strncasecmp(sigstr, "SIG", 3))
			sigstr += 3;

		for (sig = 0; sig < UC_SYSTEM_SIGNAL_COUNT; sig++)
			if (uc_system_signal_names[sig] &&
			    !strcasecmp(uc_system_signal_names[sig], sigstr))
				break;

		if (sig == UC_SYSTEM_SIGNAL_COUNT)
			return NULL;
	}
	else {
		return NULL;
	}

	/* Query current signal handler state */
	if (nargs < 2) {
		if (sigaction(sig, NULL, &sa) != 0)
			return NULL;

		if (sa.sa_handler == SIG_IGN)
			return ucv_string_new("ignore");

		if (sa.sa_handler == SIG_DFL)
			return ucv_string_new("default");

		return ucv_get(ucv_array_get(vm->signal.handler, sig));
	}

	/* Install new signal handler */
	if (ucv_type(sighandler) == UC_STRING) {
		sigstr = ucv_string_get(sighandler);

		sa.sa_flags = SA_ONSTACK | SA_RESTART;
		sigemptyset(&sa.sa_mask);

		if (!strcmp(sigstr, "ignore"))
			sa.sa_handler = SIG_IGN;
		else if (!strcmp(sigstr, "default"))
			sa.sa_handler = SIG_DFL;
		else
			return NULL;

		if (sigaction(sig, &sa, NULL) != 0)
			return NULL;

		ucv_array_set(vm->signal.handler, sig, NULL);
	}
	else if (ucv_is_callable(sighandler)) {
		if (sigaction(sig, &vm->signal.sa, NULL) != 0)
			return NULL;

		ucv_array_set(vm->signal.handler, sig, ucv_get(sighandler));
	}
	else {
		return NULL;
	}

	return ucv_get(sighandler);
}


const uc_function_list_t uc_stdlib_functions[] = {
	{ "chr",		uc_chr },
	{ "die",		uc_die },
	{ "exists",		uc_exists },
	{ "exit",		uc_exit },
	{ "filter",		uc_filter },
	{ "getenv",		uc_getenv },
	{ "hex",		uc_hex },
	{ "index",		uc_lindex },
	{ "int",		uc_int },
	{ "join",		uc_join },
	{ "keys",		uc_keys },
	{ "lc",			uc_lc },
	{ "length",		uc_length },
	{ "ltrim",		uc_ltrim },
	{ "map",		uc_map },
	{ "ord",		uc_ord },
	{ "pop",		uc_pop },
	{ "print",		uc_print },
	{ "push",		uc_push },
	{ "reverse",	uc_reverse },
	{ "rindex",		uc_rindex },
	{ "rtrim",		uc_rtrim },
	{ "shift",		uc_shift },
	{ "sort",		uc_sort },
	{ "splice",		uc_splice },
	{ "slice",		uc_slice },
	{ "split",		uc_split },
	{ "substr",		uc_substr },
	{ "time",		uc_time },
	{ "trim",		uc_trim },
	{ "type",		uc_type },
	{ "uchr",		uc_uchr },
	{ "uc",			uc_uc },
	{ "unshift",	uc_unshift },
	{ "values",		uc_values },
	{ "sprintf",	uc_sprintf },
	{ "printf",		uc_printf },
	{ "require",	uc_require },
	{ "iptoarr",	uc_iptoarr },
	{ "arrtoip",	uc_arrtoip },
	{ "match",		uc_match },
	{ "replace",	uc_replace },
	{ "json",		uc_json },
	{ "include",	uc_include },
	{ "warn",		uc_warn },
	{ "system",		uc_system },
	{ "trace",		uc_trace },
	{ "proto",		uc_proto },
	{ "sleep",		uc_sleep },
	{ "assert",		uc_assert },
	{ "render",		uc_render },
	{ "regexp",		uc_regexp },
	{ "wildcard",	uc_wildcard },
	{ "sourcepath",	uc_sourcepath },
	{ "min",		uc_min },
	{ "max",		uc_max },
	{ "b64dec",		uc_b64dec },
	{ "b64enc",		uc_b64enc },
	{ "uniq",		uc_uniq },
	{ "localtime",	uc_localtime },
	{ "gmtime",		uc_gmtime },
	{ "timelocal",	uc_timelocal },
	{ "timegm",		uc_timegm },
	{ "clock",		uc_clock },
	{ "hexdec",		uc_hexdec },
	{ "hexenc",		uc_hexenc },
	{ "gc",			uc_gc },
	{ "loadstring",	uc_loadstring },
	{ "loadfile",	uc_loadfile },
	{ "call",		uc_callfunc },
	{ "signal",		uc_signal },
};


void
uc_stdlib_load(uc_value_t *scope)
{
	uc_function_list_register(scope, uc_stdlib_functions);
}

uc_cfn_ptr_t
uc_stdlib_function(const char *name)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(uc_stdlib_functions); i++)
		if (!strcmp(uc_stdlib_functions[i].name, name))
			return uc_stdlib_functions[i].func;

	return NULL;
}
