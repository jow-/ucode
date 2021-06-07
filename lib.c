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

#include "lexer.h"
#include "compiler.h"
#include "vm.h"
#include "lib.h"
#include "source.h"

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
source_filename(uc_source *src, uint32_t line)
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
format_source_context(uc_stringbuf_t *buf, uc_source *src, size_t off, bool compact)
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
format_error_context(uc_stringbuf_t *buf, uc_source *src, uc_value_t *stacktrace, size_t off)
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

	return format_source_context(buf, src, off, false);
}

static char *uc_cast_string(uc_vm *vm, uc_value_t **v, bool *freeable) {
	if (ucv_type(*v) == UC_STRING) {
		*freeable = false;

		return _ucv_string_get(v);
	}

	*freeable = true;

	return ucv_to_string(vm, *v);
}

static double
uc_cast_double(uc_value_t *v)
{
	uc_type_t t;
	int64_t n;
	double d;

	t = uc_cast_number(v, &n, &d);
	errno = 0;

	if (t == UC_DOUBLE) {
		if (isnan(d))
			errno = EINVAL;
		else if (!isfinite(d))
			errno = EOVERFLOW;

		return d;
	}

	return (double)n;
}

static int64_t
uc_cast_int64(uc_value_t *v)
{
	uc_type_t t;
	int64_t n;
	double d;

	t = uc_cast_number(v, &n, &d);
	errno = 0;

	if (t == UC_DOUBLE) {
		if (isnan(d))
			errno = EINVAL;
		else if (!isfinite(d))
			errno = EOVERFLOW;
		else if ((double)(int64_t)d != d)
			errno = ERANGE;

		return (int64_t)d;
	}

	return n;
}

static void
uc_vm_ctx_push(uc_vm *vm)
{
	uc_value_t *ctx = NULL;
	size_t i;

	for (i = vm->callframes.count; i > 0; i--) {
		if (vm->callframes.entries[i - 1].ctx) {
			ctx = vm->callframes.entries[i - 1].ctx;
			break;
		}
	}

	uc_vm_stack_push(vm, ucv_get(ctx));
}

static uc_value_t *
uc_print_common(uc_vm *vm, size_t nargs, FILE *fh)
{
	uc_value_t *item;
	size_t reslen = 0;
	size_t len = 0;
	size_t arridx;
	char *p;

	for (arridx = 0; arridx < nargs; arridx++) {
		item = uc_get_arg(arridx);

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


static uc_value_t *
uc_print(uc_vm *vm, size_t nargs)
{
	return uc_print_common(vm, nargs, vm->output);
}

static uc_value_t *
uc_length(uc_vm *vm, size_t nargs)
{
	uc_value_t *arg = uc_get_arg(0);

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

static uc_value_t *
uc_index(uc_vm *vm, size_t nargs, bool right)
{
	uc_value_t *stack = uc_get_arg(0);
	uc_value_t *needle = uc_get_arg(1);
	const char *sstr, *nstr, *p;
	size_t arridx, len;
	ssize_t ret = -1;

	switch (ucv_type(stack)) {
	case UC_ARRAY:
		for (arridx = 0, len = ucv_array_length(stack); arridx < len; arridx++) {
			if (uc_cmp(TK_EQ, ucv_array_get(stack, arridx), needle)) {
				ret = (ssize_t)arridx;

				if (!right)
					break;
			}
		}

		return ucv_int64_new(ret);

	case UC_STRING:
		sstr = ucv_string_get(stack);
		nstr = needle ? ucv_string_get(needle) : NULL;
		len = needle ? strlen(nstr) : 0;

		for (p = sstr; *p && len; p++) {
			if (!strncmp(p, nstr, len)) {
				ret = (ssize_t)(p - sstr);

				if (!right)
					break;
			}
		}

		return ucv_int64_new(ret);

	default:
		return NULL;
	}
}

static uc_value_t *
uc_lindex(uc_vm *vm, size_t nargs)
{
	return uc_index(vm, nargs, false);
}

static uc_value_t *
uc_rindex(uc_vm *vm, size_t nargs)
{
	return uc_index(vm, nargs, true);
}

static uc_value_t *
uc_push(uc_vm *vm, size_t nargs)
{
	uc_value_t *arr = uc_get_arg(0);
	uc_value_t *item = NULL;
	size_t arridx;

	if (ucv_type(arr) != UC_ARRAY)
		return NULL;

	for (arridx = 1; arridx < nargs; arridx++) {
		item = uc_get_arg(arridx);
		ucv_array_push(arr, ucv_get(item));
	}

	return ucv_get(item);
}

static uc_value_t *
uc_pop(uc_vm *vm, size_t nargs)
{
	uc_value_t *arr = uc_get_arg(0);

	return ucv_array_pop(arr);
}

static uc_value_t *
uc_shift(uc_vm *vm, size_t nargs)
{
	uc_value_t *arr = uc_get_arg(0);

	return ucv_array_shift(arr);
}

static uc_value_t *
uc_unshift(uc_vm *vm, size_t nargs)
{
	uc_value_t *arr = uc_get_arg(0);
	uc_value_t *item = NULL;
	size_t i;

	if (ucv_type(arr) != UC_ARRAY)
		return NULL;

	for (i = 1; i < nargs; i++) {
		item = uc_get_arg(i);
		ucv_array_unshift(arr, ucv_get(item));
	}

	return ucv_get(item);
}

static uc_value_t *
uc_chr(uc_vm *vm, size_t nargs)
{
	uc_value_t *rv = NULL;
	size_t idx;
	int64_t n;
	char *str;

	if (!nargs)
		return ucv_string_new_length("", 0);

	str = xalloc(nargs);

	for (idx = 0; idx < nargs; idx++) {
		n = uc_cast_int64(uc_get_arg(idx));

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

static uc_value_t *
uc_die(uc_vm *vm, size_t nargs)
{
	uc_value_t *msg = uc_get_arg(0);
	bool freeable = false;
	char *s;

	s = msg ? uc_cast_string(vm, &msg, &freeable) : "Died";

	uc_vm_raise_exception(vm, EXCEPTION_USER, "%s", s);

	if (freeable)
		free(s);

	return NULL;
}

static uc_value_t *
uc_exists(uc_vm *vm, size_t nargs)
{
	uc_value_t *obj = uc_get_arg(0);
	uc_value_t *key = uc_get_arg(1);
	bool found, freeable;
	char *k;

	if (ucv_type(obj) != UC_OBJECT)
		return false;

	k = uc_cast_string(vm, &key, &freeable);

	ucv_object_get(obj, k, &found);

	if (freeable)
		free(k);

	return ucv_boolean_new(found);
}

__attribute__((noreturn)) static uc_value_t *
uc_exit(uc_vm *vm, size_t nargs)
{
	int64_t n = uc_cast_int64(uc_get_arg(0));

	exit(n);
}

static uc_value_t *
uc_getenv(uc_vm *vm, size_t nargs)
{
	uc_value_t *key = uc_get_arg(0);
	char *k = ucv_string_get(key);
	char *val = k ? getenv(k) : NULL;

	return val ? ucv_string_new(val) : NULL;
}

static uc_value_t *
uc_filter(uc_vm *vm, size_t nargs)
{
	uc_value_t *obj = uc_get_arg(0);
	uc_value_t *func = uc_get_arg(1);
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

		if (uc_val_is_truish(rv))
			ucv_array_push(arr, ucv_get(ucv_array_get(obj, arridx)));

		ucv_put(rv);
	}

	return arr;
}

static uc_value_t *
uc_hex(uc_vm *vm, size_t nargs)
{
	uc_value_t *val = uc_get_arg(0);
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

static uc_value_t *
uc_int(uc_vm *vm, size_t nargs)
{
	int64_t n = uc_cast_int64(uc_get_arg(0));

	if (errno == EINVAL || errno == EOVERFLOW)
		return ucv_double_new(NAN);

	return ucv_int64_new(n);
}

static uc_value_t *
uc_join(uc_vm *vm, size_t nargs)
{
	uc_value_t *sep = uc_get_arg(0);
	uc_value_t *arr = uc_get_arg(1);
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

static uc_value_t *
uc_keys(uc_vm *vm, size_t nargs)
{
	uc_value_t *obj = uc_get_arg(0);
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

static uc_value_t *
uc_lc(uc_vm *vm, size_t nargs)
{
	char *str = ucv_to_string(vm, uc_get_arg(0));
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

static uc_value_t *
uc_map(uc_vm *vm, size_t nargs)
{
	uc_value_t *obj = uc_get_arg(0);
	uc_value_t *func = uc_get_arg(1);
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

static uc_value_t *
uc_ord(uc_vm *vm, size_t nargs)
{
	uc_value_t *obj = uc_get_arg(0);
	uc_value_t *rv, *pos;
	const char *str;
	size_t i, len;
	int64_t n;

	if (ucv_type(obj) != UC_STRING)
		return NULL;

	str = ucv_string_get(obj);
	len = ucv_string_length(obj);

	if (nargs == 1)
		return str[0] ? ucv_int64_new((int64_t)str[0]) : NULL;

	rv = ucv_array_new(vm);

	for (i = 1; i < nargs; i++) {
		pos = uc_get_arg(i);

		if (ucv_type(pos) == UC_INTEGER) {
			n = ucv_int64_get(pos);

			if (n < 0)
				n += len;

			if (n >= 0 && (uint64_t)n < len) {
				ucv_array_push(rv, ucv_int64_new((int64_t)str[n]));
				continue;
			}
		}

		ucv_array_push(rv, NULL);
	}

	return rv;
}

static uc_value_t *
uc_type(uc_vm *vm, size_t nargs)
{
	uc_value_t *v = uc_get_arg(0);
	uc_type_t t = ucv_type(v);

	switch (t) {
	case UC_CFUNCTION:
	case UC_FUNCTION:
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

static uc_value_t *
uc_reverse(uc_vm *vm, size_t nargs)
{
	uc_value_t *obj = uc_get_arg(0);
	uc_value_t *rv = NULL;
	size_t len, arridx;
	const char *str;
	char *dup, *p;

	if (ucv_type(obj) == UC_ARRAY) {
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


static struct {
	uc_vm *vm;
	bool ex;
	uc_value_t *fn;
} sort_ctx;

static int
default_cmp(uc_value_t *v1, uc_value_t *v2)
{
	uc_type_t t1, t2;
	int64_t n1, n2;
	double d1, d2;
	char *s1, *s2;
	bool f1, f2;

	if (ucv_type(v1) == UC_INTEGER || ucv_type(v1) == UC_DOUBLE ||
	    ucv_type(v2) == UC_INTEGER || ucv_type(v2) == UC_DOUBLE) {
		t1 = uc_cast_number(v1, &n1, &d1);
		t2 = uc_cast_number(v2, &n2, &d2);

		if (t1 == UC_DOUBLE || t2 == UC_DOUBLE) {
			d1 = (t1 == UC_DOUBLE) ? d1 : (double)n1;
			d2 = (t2 == UC_DOUBLE) ? d2 : (double)n2;

			if (d1 < d2)
				return -1;

			if (d1 > d2)
				return 1;

			return 0;
		}

		if (n1 < n2)
			return -1;

		if (n1 > n2)
			return 1;

		return 0;
	}

	s1 = uc_cast_string(sort_ctx.vm, &v1, &f1);
	s2 = uc_cast_string(sort_ctx.vm, &v2, &f2);

	n1 = strcmp(s1, s2);

	if (f1) free(s1);
	if (f2) free(s2);

	return n1;
}

static int
sort_fn(const void *k1, const void *k2)
{
	uc_value_t * const *v1 = k1;
	uc_value_t * const *v2 = k2;
	uc_value_t *rv;
	uc_type_t t;
	int64_t n;
	double d;

	if (!sort_ctx.fn)
		return default_cmp(*v1, *v2);

	if (sort_ctx.ex)
		return 0;

	uc_vm_ctx_push(sort_ctx.vm);
	uc_vm_stack_push(sort_ctx.vm, ucv_get(sort_ctx.fn));
	uc_vm_stack_push(sort_ctx.vm, ucv_get(*v1));
	uc_vm_stack_push(sort_ctx.vm, ucv_get(*v2));

	if (uc_vm_call(sort_ctx.vm, true, 2)) {
		sort_ctx.ex = true;

		return 0;
	}

	rv = uc_vm_stack_pop(sort_ctx.vm);
	t = uc_cast_number(rv, &n, &d);

	if (t == UC_DOUBLE) {
		if (d < 0)
			n = -1;

		if (d > 0)
			n = 1;
	}
	else {
		if (n < 0)
			n = -1;

		if (n > 0)
			n = 1;
	}

	ucv_put(rv);

	return n;
}

static uc_value_t *
uc_sort(uc_vm *vm, size_t nargs)
{
	uc_value_t *arr = uc_get_arg(0);
	uc_value_t *fn = uc_get_arg(1);

	if (ucv_type(arr) != UC_ARRAY)
		return NULL;

	sort_ctx.vm = vm;
	sort_ctx.fn = fn;

	ucv_array_sort(arr, sort_fn);

	return sort_ctx.ex ? NULL : ucv_get(arr);
}

static uc_value_t *
uc_splice(uc_vm *vm, size_t nargs)
{
	uc_value_t *arr = uc_get_arg(0);
	int64_t ofs = uc_cast_int64(uc_get_arg(1));
	int64_t remlen = uc_cast_int64(uc_get_arg(2));
	size_t arrlen, addlen, idx;

	if (ucv_type(arr) != UC_ARRAY)
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
			ucv_get(uc_get_arg(3 + idx)));

	return ucv_get(arr);
}

static uc_value_t *
uc_split(uc_vm *vm, size_t nargs)
{
	uc_value_t *str = uc_get_arg(0);
	uc_value_t *sep = uc_get_arg(1);
	uc_value_t *arr = NULL;
	const char *p, *sepstr, *splitstr;
	int eflags = 0, res;
	regmatch_t pmatch;
	uc_regexp_t *re;
	size_t seplen;

	if (!sep || ucv_type(str) != UC_STRING)
		return NULL;

	arr = ucv_array_new(vm);
	splitstr = ucv_string_get(str);

	if (ucv_type(sep) == UC_REGEXP) {
		re = (uc_regexp_t *)sep;

		while (true) {
			res = regexec(&re->regexp, splitstr, 1, &pmatch, eflags);

			if (res == REG_NOMATCH)
				break;

			ucv_array_push(arr, ucv_string_new_length(splitstr, pmatch.rm_so));

			splitstr += pmatch.rm_eo;
			eflags |= REG_NOTBOL;
		}

		ucv_array_push(arr, ucv_string_new(splitstr));
	}
	else if (ucv_type(sep) == UC_STRING) {
		sepstr = ucv_string_get(sep);

		for (p = splitstr, seplen = strlen(sepstr); *p; p++) {
			if (!strncmp(p, sepstr, seplen)) {
				if (*sepstr || p > splitstr)
					ucv_array_push(arr, ucv_string_new_length(splitstr, p - splitstr));

				splitstr = p + seplen;
				p = splitstr - (*sepstr ? 1 : 0);
			}
		}

		ucv_array_push(arr, ucv_string_new_length(splitstr, p - splitstr));
	}
	else {
		ucv_put(arr);

		return NULL;
	}

	return arr;
}

static uc_value_t *
uc_substr(uc_vm *vm, size_t nargs)
{
	uc_value_t *str = uc_get_arg(0);
	int64_t ofs = uc_cast_int64(uc_get_arg(1));
	int64_t sublen = uc_cast_int64(uc_get_arg(2));
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

static uc_value_t *
uc_time(uc_vm *vm, size_t nargs)
{
	time_t t = time(NULL);

	return ucv_int64_new((int64_t)t);
}

static uc_value_t *
uc_uc(uc_vm *vm, size_t nargs)
{
	char *str = ucv_to_string(vm, uc_get_arg(0));
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

static uc_value_t *
uc_uchr(uc_vm *vm, size_t nargs)
{
	uc_value_t *rv = NULL;
	size_t idx, ulen;
	char *p, *str;
	int64_t n;
	int rem;

	for (idx = 0, ulen = 0; idx < nargs; idx++) {
		n = uc_cast_int64(uc_get_arg(idx));

		if (errno == EINVAL || errno == EOVERFLOW || n < 0 || n > 0x10FFFF)
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
		n = uc_cast_int64(uc_get_arg(idx));

		if (errno == EINVAL || errno == EOVERFLOW || n < 0 || n > 0x10FFFF)
			n = 0xFFFD;

		if (!utf8enc(&p, &rem, n))
			break;
	}

	rv = ucv_string_new_length(str, ulen);

	free(str);

	return rv;
}

static uc_value_t *
uc_values(uc_vm *vm, size_t nargs)
{
	uc_value_t *obj = uc_get_arg(0);
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
uc_trim_common(uc_vm *vm, size_t nargs, bool start, bool end)
{
	uc_value_t *str = uc_get_arg(0);
	uc_value_t *chr = uc_get_arg(1);
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

static uc_value_t *
uc_trim(uc_vm *vm, size_t nargs)
{
	return uc_trim_common(vm, nargs, true, true);
}

static uc_value_t *
uc_ltrim(uc_vm *vm, size_t nargs)
{
	return uc_trim_common(vm, nargs, true, false);
}

static uc_value_t *
uc_rtrim(uc_vm *vm, size_t nargs)
{
	return uc_trim_common(vm, nargs, false, true);
}

static void
uc_printf_common(uc_vm *vm, size_t nargs, uc_stringbuf_t *buf)
{
	uc_value_t *fmt = uc_get_arg(0);
	char *fp, sfmt[sizeof("%0- 123456789.123456789%")];
	union { char *s; int64_t n; double d; } arg;
	const char *fstr, *last, *p;
	uc_type_t t = UC_NULL;
	size_t argidx = 1;
	int i, pad_size;

	if (ucv_type(fmt) == UC_STRING)
		fstr = ucv_string_get(fmt);
	else
		fstr = "";

	for (last = p = fstr; *p; p++) {
		if (*p == '%') {
			ucv_stringbuf_addstr(buf, last, p - last);

			last = p++;

			fp = sfmt;
			*fp++ = '%';

			memset(&arg, 0, sizeof(arg));

			while (*p != '\0' && strchr("0- ", *p)) {
				if (fp + 1 >= sfmt + sizeof(sfmt))
					goto next;

				*fp++ = *p++;
			}

			if (*p >= '1' && *p <= '9') {
				if (fp + 1 >= sfmt + sizeof(sfmt))
					goto next;

				*fp++ = *p++;

				while (isdigit(*p)) {
					if (fp + 1 >= sfmt + sizeof(sfmt))
						goto next;

					*fp++ = *p++;
				}
			}

			if (*p == '.') {
				if (fp + 1 >= sfmt + sizeof(sfmt))
					goto next;

				*fp++ = *p++;

				if (*p == '-') {
					if (fp + 1 >= sfmt + sizeof(sfmt))
						goto next;

					*fp++ = *p++;
				}

				while (isdigit(*p)) {
					if (fp + 1 >= sfmt + sizeof(sfmt))
						goto next;

					*fp++ = *p++;
				}
			}

			if (!strncmp(p, "hh", 2) || !strncmp(p, "ll", 2)) {
				if (fp + 2 >= sfmt + sizeof(sfmt))
					goto next;

				*fp++ = *p++;
				*fp++ = *p++;
			}
			else if (*p == 'h' || *p == 'l') {
				if (fp + 1 >= sfmt + sizeof(sfmt))
					goto next;

				*fp++ = *p++;
			}

			switch (*p) {
			case 'd':
			case 'i':
			case 'o':
			case 'u':
			case 'x':
			case 'X':
				t = UC_INTEGER;

				if (argidx < nargs)
					arg.n = uc_cast_int64(uc_get_arg(argidx++));
				else
					arg.n = 0;

				break;

			case 'e':
			case 'E':
			case 'f':
			case 'F':
			case 'g':
			case 'G':
				t = UC_DOUBLE;

				if (argidx < nargs)
					arg.d = uc_cast_double(uc_get_arg(argidx++));
				else
					arg.d = 0;

				break;

			case 'c':
				t = UC_INTEGER;

				if (argidx < nargs)
					arg.n = uc_cast_int64(uc_get_arg(argidx++)) & 0xff;
				else
					arg.n = 0;

				break;

			case 's':
				t = UC_STRING;

				if (argidx < nargs)
					arg.s = ucv_to_string(vm, uc_get_arg(argidx++));
				else
					arg.s = NULL;

				arg.s = arg.s ? arg.s : xstrdup("(null)");

				break;

			case 'J':
				t = UC_STRING;

				pad_size = 0;

				for (i = 0; sfmt + i < fp; i++) {
					if (sfmt[i] == '.') {
						pad_size = 1 + atoi(&sfmt[i + 1]);
						fp = &sfmt[i];
						break;
					}
				}

				if (argidx < nargs) {
					arg.s = ucv_to_jsonstring_formatted(vm,
						uc_get_arg(argidx++),
						pad_size > 0 ? (pad_size > 1 ? ' ' : '\t') : '\0',
						pad_size > 0 ? (pad_size > 1 ? pad_size - 1 : 1) : 0);
				}
				else {
					arg.s = NULL;
				}

				arg.s = arg.s ? arg.s : xstrdup("null");

				break;

			case '%':
				t = UC_NULL;

				break;

			case '\0':
				p--;
				/* fall through */

			default:
				goto next;
			}

			if (fp + 2 >= sfmt + sizeof(sfmt))
				goto next;

			*fp++ = (t == UC_STRING) ? 's' : *p;
			*fp = 0;

			switch (t) {
			case UC_INTEGER:
				ucv_stringbuf_printf(buf, sfmt, arg.n);
				break;

			case UC_DOUBLE:
				ucv_stringbuf_printf(buf, sfmt, arg.d);
				break;

			case UC_STRING:
				ucv_stringbuf_printf(buf, sfmt, arg.s);
				break;

			default:
				ucv_stringbuf_addstr(buf, sfmt, strlen(sfmt));
				break;
			}

			last = p + 1;

next:
			if (t == UC_STRING)
				free(arg.s);

			continue;
		}
	}

	ucv_stringbuf_addstr(buf, last, p - last);
}

static uc_value_t *
uc_sprintf(uc_vm *vm, size_t nargs)
{
	uc_stringbuf_t *buf = ucv_stringbuf_new();

	uc_printf_common(vm, nargs, buf);

	return ucv_stringbuf_finish(buf);
}

static uc_value_t *
uc_printf(uc_vm *vm, size_t nargs)
{
	uc_stringbuf_t *buf = xprintbuf_new();
	size_t len;

	uc_printf_common(vm, nargs, buf);

	len = fwrite(buf->buf, 1, printbuf_length(buf), vm->output);

	printbuf_free(buf);

	return ucv_int64_new(len);
}

static bool
uc_require_so(uc_vm *vm, const char *path, uc_value_t **res)
{
	void (*init)(uc_value_t *);
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

	init(scope);

	*res = scope;

	return true;
}

static bool
uc_require_ucode(uc_vm *vm, const char *path, uc_value_t *scope, uc_value_t **res)
{
	uc_exception_type_t extype;
	uc_function_t *function;
	uc_value_t *prev_scope;
	uc_value_t *closure;
	uc_source *source;
	struct stat st;
	char *err;

	if (stat(path, &st))
		return false;

	source = uc_source_new_file(path);

	if (!source) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Unable to open file '%s': %s", path, strerror(errno));

		return true;
	}

	function = uc_compile(vm->config, source, &err);

	if (!function) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Unable to compile module '%s':\n%s", path, err);

		uc_source_put(source);
		free(err);

		return true;
	}

	closure = ucv_closure_new(vm, function, false);

	uc_vm_stack_push(vm, closure);

	prev_scope = vm->globals;
	vm->globals = scope ? scope : prev_scope;

	extype = uc_vm_call(vm, false, 0);

	vm->globals = prev_scope;

	if (extype == EXCEPTION_NONE)
		*res = uc_vm_stack_pop(vm);

	uc_source_put(source);

	return true;
}

static bool
uc_require_path(uc_vm *vm, const char *path_template, const char *name, uc_value_t **res)
{
	uc_stringbuf_t *buf = xprintbuf_new();
	const char *p, *q, *last;
	bool rv = false;

	*res = NULL;

	p = strchr(path_template, '*');

	if (!p)
		goto invalid;

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
			goto invalid;
		}
	}

	if (!strcmp(p + 1, ".so"))
		rv = uc_require_so(vm, buf->buf, res);
	else if (!strcmp(p + 1, ".uc"))
		rv = uc_require_ucode(vm, buf->buf, NULL, res);

invalid:
	printbuf_free(buf);

	return rv;
}

static uc_value_t *
uc_require(uc_vm *vm, size_t nargs)
{
	uc_value_t *val = uc_get_arg(0);
	uc_value_t *search, *se, *res;
	size_t arridx, arrlen;
	const char *name;

	if (ucv_type(val) != UC_STRING)
		return NULL;

	name = ucv_string_get(val);
	search = ucv_property_get(vm->globals, "REQUIRE_SEARCH_PATH");

	if (ucv_type(search) != UC_ARRAY) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Global require search path not set");

		return NULL;
	}

	for (arridx = 0, arrlen = ucv_array_length(search); arridx < arrlen; arridx++) {
		se = ucv_array_get(search, arridx);

		if (ucv_type(se) != UC_STRING)
			continue;

		if (uc_require_path(vm, ucv_string_get(se), name, &res))
			return res;
	}

	uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
	                      "No module named '%s' could be found", name);

	return NULL;
}

static uc_value_t *
uc_iptoarr(uc_vm *vm, size_t nargs)
{
	uc_value_t *ip = uc_get_arg(0);
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

static uc_value_t *
uc_arrtoip(uc_vm *vm, size_t nargs)
{
	uc_value_t *arr = uc_get_arg(0);
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

static uc_value_t *
uc_match(uc_vm *vm, size_t nargs)
{
	uc_value_t *subject = uc_get_arg(0);
	uc_value_t *pattern = uc_get_arg(1);
	uc_value_t *rv = NULL, *m;
	regmatch_t pmatch[10];
	int eflags = 0, res;
	uc_regexp_t *re;
	bool freeable;
	char *p;
	size_t i;

	if (ucv_type(pattern) != UC_REGEXP || !subject)
		return NULL;

	p = uc_cast_string(vm, &subject, &freeable);
	re = (uc_regexp_t *)pattern;

	while (true) {
		res = regexec(&re->regexp, p, ARRAY_SIZE(pmatch), pmatch, eflags);

		if (res == REG_NOMATCH)
			break;

		m = ucv_array_new(vm);

		for (i = 0; i < ARRAY_SIZE(pmatch) && pmatch[i].rm_so != -1; i++) {
			ucv_array_push(m,
				ucv_string_new_length(p + pmatch[i].rm_so,
				                      pmatch[i].rm_eo - pmatch[i].rm_so));
		}

		if (re->global) {
			if (!rv)
				rv = ucv_array_new(vm);

			ucv_array_push(rv, m);

			p += pmatch[0].rm_eo;
			eflags |= REG_NOTBOL;
		}
		else {
			rv = m;
			break;
		}
	}

	if (freeable)
		free(p);

	return rv;
}

static uc_value_t *
uc_replace_cb(uc_vm *vm, uc_value_t *func,
              const char *subject, regmatch_t *pmatch, size_t plen,
              uc_stringbuf_t *resbuf)
{
	uc_value_t *rv;
	size_t i;

	uc_vm_ctx_push(vm);
	uc_vm_stack_push(vm, ucv_get(func));

	for (i = 0; i < plen && pmatch[i].rm_so != -1; i++) {
		uc_vm_stack_push(vm,
			ucv_string_new_length(subject + pmatch[i].rm_so,
			                      pmatch[i].rm_eo - pmatch[i].rm_so));
	}

	if (uc_vm_call(vm, true, i))
		return NULL;

	rv = uc_vm_stack_pop(vm);

	ucv_to_stringbuf(vm, resbuf, rv, false);

	ucv_put(rv);

	return NULL;
}

static void
uc_replace_str(uc_vm *vm, uc_value_t *str,
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

static uc_value_t *
uc_replace(uc_vm *vm, size_t nargs)
{
	char *sb = NULL, *pt = NULL, *p, *l;
	uc_value_t *subject = uc_get_arg(0);
	uc_value_t *pattern = uc_get_arg(1);
	uc_value_t *replace = uc_get_arg(2);
	bool sb_freeable, pt_freeable;
	uc_value_t *rv = NULL;
	uc_stringbuf_t *resbuf;
	regmatch_t pmatch[10];
	int eflags = 0, res;
	uc_regexp_t *re;
	size_t pl;

	if (!pattern || !subject || !replace)
		return NULL;

	sb = uc_cast_string(vm, &subject, &sb_freeable);
	resbuf = ucv_stringbuf_new();

	if (ucv_type(pattern) == UC_REGEXP) {
		re = (uc_regexp_t *)pattern;
		p = sb;

		while (true) {
			res = regexec(&re->regexp, p, ARRAY_SIZE(pmatch), pmatch, eflags);

			if (res == REG_NOMATCH)
				break;

			ucv_stringbuf_addstr(resbuf, p, pmatch[0].rm_so);

			if (ucv_is_callable(replace)) {
				rv = uc_replace_cb(vm, replace, p, pmatch, ARRAY_SIZE(pmatch), resbuf);

				if (rv) {
					if (sb_freeable)
						free(sb);

					return rv;
				}
			}
			else {
				uc_replace_str(vm, replace, p, pmatch, ARRAY_SIZE(pmatch), resbuf);
			}

			p += pmatch[0].rm_eo;

			if (re->global)
				eflags |= REG_NOTBOL;
			else
				break;
		}

		ucv_stringbuf_addstr(resbuf, p, strlen(p));
	}
	else {
		pt = uc_cast_string(vm, &pattern, &pt_freeable);
		pl = strlen(pt);

		for (l = p = sb; *p; p++) {
			if (!strncmp(p, pt, pl)) {
				ucv_stringbuf_addstr(resbuf, l, p - l);

				pmatch[0].rm_so = p - l;
				pmatch[0].rm_eo = pmatch[0].rm_so + pl;

				if (ucv_is_callable(replace)) {
					rv = uc_replace_cb(vm, replace, l, pmatch, 1, resbuf);

					if (rv) {
						if (sb_freeable)
							free(sb);

						if (pt_freeable)
							free(pt);

						return rv;
					}
				}
				else {
					uc_replace_str(vm, replace, l, pmatch, 1, resbuf);
				}

				l = p + pl;
				p += pl - 1;
			}
		}

		ucv_stringbuf_addstr(resbuf, l, strlen(l));

		if (pt_freeable)
			free(pt);
	}

	if (sb_freeable)
		free(sb);

	return ucv_stringbuf_finish(resbuf);
}

static uc_value_t *
uc_json(uc_vm *vm, size_t nargs)
{
	uc_value_t *rv, *src = uc_get_arg(0);
	struct json_tokener *tok = NULL;
	enum json_tokener_error err;
	json_object *jso;
	const char *str;
	size_t len;

	if (ucv_type(src) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
		                      "Passed value is not a string");

		return NULL;
	}

	tok = xjs_new_tokener();
	str = ucv_string_get(src);
	len = ucv_string_length(src);

	/* NB: the len + 1 here is intentional to pass the terminating \0 byte
	 * to the json-c parser. This is required to work-around upstream
	 * issue #681 <https://github.com/json-c/json-c/issues/681> */
	jso = json_tokener_parse_ex(tok, str, len + 1);
	err = json_tokener_get_error(tok);

	if (err == json_tokener_continue) {
		json_object_put(jso);
		uc_vm_raise_exception(vm, EXCEPTION_SYNTAX,
		                      "Unexpected end of string in JSON data");

		return NULL;
	}
	else if (err != json_tokener_success) {
		json_object_put(jso);
		uc_vm_raise_exception(vm, EXCEPTION_SYNTAX,
		                      "Failed to parse JSON string: %s",
		                      json_tokener_error_desc(err));

		return NULL;
	}
	else if (json_tokener_get_parse_end(tok) < len) {
		json_object_put(jso);
		uc_vm_raise_exception(vm, EXCEPTION_SYNTAX,
		                      "Trailing garbage after JSON data");

		return NULL;
	}

	json_tokener_free(tok);

	rv = ucv_from_json(vm, jso);

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

	if (curpath) {
		dup = strdup(curpath);

		if (!dup)
			return NULL;

		len = asprintf(&res, "%s/%s", dirname(dup), incpath);

		free(dup);
	}
	else {
		len = asprintf(&res, "./%s", incpath);
	}

	if (len == -1)
		return NULL;

	dup = realpath(res, NULL);

	free(res);

	return dup;
}

static uc_value_t *
uc_include(uc_vm *vm, size_t nargs)
{
	uc_value_t *path = uc_get_arg(0);
	uc_value_t *scope = uc_get_arg(1);
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

	p = include_path(closure->function->source->filename, ucv_string_get(path));

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

		ucv_prototype_set(sc, ucv_get(vm->globals));
	}
	else {
		sc = ucv_get(vm->globals);
	}

	if (uc_require_ucode(vm, p, sc, &rv))
		ucv_put(rv);

	ucv_put(sc);
	free(p);

	return NULL;
}

static uc_value_t *
uc_render(uc_vm *vm, size_t nargs)
{
	uc_string_t *ustr = NULL;
	FILE *mem, *prev;
	size_t len = 0;

	mem = open_memstream((char **)&ustr, &len);

	if (!mem)
		goto out;

	/* reserve space for uc_string_t header... */
	if (fseek(mem, sizeof(*ustr), SEEK_SET))
		goto out;

	/* divert VM output to memory fd */
	prev = vm->output;
	vm->output = mem;

	/* execute include */
	(void) uc_include(vm, nargs);

	/* restore previous VM output */
	vm->output = prev;
	fclose(mem);

	/* update uc_string_t length */
	ustr->header.type = UC_STRING;
	ustr->header.refcount = 1;
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

static uc_value_t *
uc_warn(uc_vm *vm, size_t nargs)
{
	return uc_print_common(vm, nargs, stderr);
}

static uc_value_t *
uc_system(uc_vm *vm, size_t nargs)
{
	uc_value_t *cmdline = uc_get_arg(0);
	uc_value_t *timeout = uc_get_arg(1);
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

		if (waitpid(cld, &rc, 0) < 0) {
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

static uc_value_t *
uc_trace(uc_vm *vm, size_t nargs)
{
	uc_value_t *level = uc_get_arg(0);
	uint8_t prev_level;

	if (ucv_type(level) != UC_INTEGER) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Invalid level specified");

		return NULL;
	}

	prev_level = vm->trace;
	vm->trace = ucv_int64_get(level);

	return ucv_int64_new(prev_level);
}

static uc_value_t *
uc_proto(uc_vm *vm, size_t nargs)
{
	uc_value_t *val = uc_get_arg(0);
	uc_value_t *proto = NULL;

	if (nargs < 2)
		return ucv_get(ucv_prototype_get(val));

	proto = uc_get_arg(1);

	if (!ucv_prototype_set(val, proto))
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Passed value is neither a prototype, ressource or object");

	ucv_get(proto);

	return ucv_get(val);
}

static uc_value_t *
uc_sleep(uc_vm *vm, size_t nargs)
{
	uc_value_t *duration = uc_get_arg(0);
	struct timeval tv;
	int64_t ms;

	ms = uc_cast_int64(duration);

	if (errno != 0 || ms <= 0)
		return ucv_boolean_new(false);

	tv.tv_sec = ms / 1000;
	tv.tv_usec = (ms % 1000) * 1000;

	select(0, NULL, NULL, NULL, &tv);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_assert(uc_vm *vm, size_t nargs)
{
	uc_value_t *cond = uc_get_arg(0);
	uc_value_t *msg = uc_get_arg(1);
	bool freeable = false;
	char *s;

	if (!uc_val_is_truish(cond)) {
		s = msg ? uc_cast_string(vm, &msg, &freeable) : "Assertion failed";

		uc_vm_raise_exception(vm, EXCEPTION_USER, "%s", s);

		if (freeable)
			free(s);

		return NULL;
	}

	return ucv_get(cond);
}

static uc_value_t *
uc_regexp(uc_vm *vm, size_t nargs)
{
	bool icase = false, newline = false, global = false, freeable;
	uc_value_t *source = uc_get_arg(0);
	uc_value_t *flags = uc_get_arg(1);
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

static uc_value_t *
uc_wildcard(uc_vm *vm, size_t nargs)
{
	uc_value_t *subject = uc_get_arg(0);
	uc_value_t *pattern = uc_get_arg(1);
	uc_value_t *icase = uc_get_arg(2);
	int flags = 0, rv;
	bool freeable;
	char *s;

	if (!subject || ucv_type(pattern) != UC_STRING)
		return NULL;

	if (uc_val_is_truish(icase))
		flags |= FNM_CASEFOLD;

	s = uc_cast_string(vm, &subject, &freeable);
	rv = fnmatch(ucv_string_get(pattern), s, flags);

	if (freeable)
		free(s);

	return ucv_boolean_new(rv == 0);
}

static uc_value_t *
uc_sourcepath(uc_vm *vm, size_t nargs)
{
	uc_value_t *calldepth = uc_get_arg(0);
	uc_value_t *dironly = uc_get_arg(1);
	uc_value_t *rv = NULL;
	uc_callframe *frame;
	char *path = NULL;
	int64_t depth;
	size_t i;

	depth = uc_cast_int64(calldepth);

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

		path = realpath(frame->closure->function->source->filename, NULL);
		break;
	}

	if (path) {
		if (uc_val_is_truish(dironly))
			rv = ucv_string_new(dirname(path));
		else
			rv = ucv_string_new(path);

		free(path);
	}

	return rv;
}

static uc_value_t *
uc_min_max(uc_vm *vm, size_t nargs, int cmp)
{
	uc_value_t *rv = NULL, *val;
	bool set = false;
	size_t i;

	for (i = 0; i < nargs; i++) {
		val = uc_get_arg(i);

		if (!set || uc_cmp(cmp, val, rv)) {
			set = true;
			rv = val;
		}
	}

	return ucv_get(rv);
}

static uc_value_t *
uc_min(uc_vm *vm, size_t nargs)
{
	return uc_min_max(vm, nargs, TK_LT);
}

static uc_value_t *
uc_max(uc_vm *vm, size_t nargs)
{
	return uc_min_max(vm, nargs, TK_GT);
}

static const uc_cfunction_list functions[] = {
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
	{ "max",		uc_max }
};


void
uc_load_stdlib(uc_value_t *scope)
{
	uc_add_proto_functions(scope, functions);
}

uc_value_t *
uc_alloc_global(uc_vm *vm)
{
	const char *path[] = { LIB_SEARCH_PATH };
	uc_value_t *global, *arr;
	size_t i;

	global = ucv_object_new(vm);

	/* build default require() search path */
	arr = ucv_array_new(vm);

	for (i = 0; i < ARRAY_SIZE(path); i++)
		ucv_array_push(arr, ucv_string_new(path[i]));

	ucv_object_add(global, "REQUIRE_SEARCH_PATH", arr);

	/* register global math constants */
	ucv_object_add(global, "NaN", ucv_double_new(NAN));
	ucv_object_add(global, "Infinity", ucv_double_new(INFINITY));

	/* register global property */
	ucv_object_add(global, "global", ucv_get(global));

	return global;
}
