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

#include "lexer.h"
#include "compiler.h"
#include "vm.h"
#include "lib.h"
#include "object.h"


const uc_ops uc = {
	.value = {
		.proto = uc_prototype_new,
		.cfunc = uc_cfunction_new,
		.dbl = uc_double_new,
		.regexp = uc_regexp_new,
		.tonumber = uc_cast_number,
		.ressource = uc_ressource_new
	},

	.ressource = {
		.define = uc_ressource_type_add,
		.create = uc_ressource_new,
		.data = uc_ressource_dataptr,
		.proto = uc_ressource_prototype
	},

	.vm = {
		.call = uc_vm_call,
		.peek = uc_vm_stack_peek,
		.pop = uc_vm_stack_pop,
		.push = uc_vm_stack_push,
		.raise = uc_vm_raise_exception
	}
};

const uc_ops *ops = &uc;

__attribute__((format(printf, 3, 5))) static void
snprintf_append(char **dptr, size_t *dlen, const char *fmt, ssize_t sz, ...)
{
	va_list ap;
	char *tmp;
	int n;

	va_start(ap, sz);
	n = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	if (sz >= 0 && n > sz)
		n = sz;

	tmp = xrealloc(*dptr, *dlen + n + 1);

	va_start(ap, sz);
	vsnprintf(tmp + *dlen, n + 1, fmt, ap);
	va_end(ap);

	*dptr = tmp;
	*dlen += n;
}

#define sprintf_append(dptr, dlen, fmt, ...) \
	snprintf_append(dptr, dlen, fmt, -1, ##__VA_ARGS__)

static void
format_context_line(char **msg, size_t *msglen, const char *line, size_t off, bool compact)
{
	const char *p;
	int padlen, i;

	for (p = line, padlen = 0; *p != '\n' && *p != '\0'; p++) {
		if (compact && (p - line) == off)
			sprintf_append(msg, msglen, "\033[22m");

		switch (*p) {
		case '\t':
			sprintf_append(msg, msglen, "    ");
			if (p < line + off)
				padlen += 4;
			break;

		case '\r':
		case '\v':
			sprintf_append(msg, msglen, " ");
			if (p < line + off)
				padlen++;
			break;

		default:
			sprintf_append(msg, msglen, "%c", *p);
			if (p < line + off)
				padlen++;
		}
	}

	if (compact) {
		sprintf_append(msg, msglen, "\033[m\n");

		return;
	}

	sprintf_append(msg, msglen, "`\n  ");

	if (padlen < strlen("Near here ^")) {
		for (i = 0; i < padlen; i++)
			sprintf_append(msg, msglen, " ");

		sprintf_append(msg, msglen, "^-- Near here\n");
	}
	else {
		sprintf_append(msg, msglen, "Near here ");

		for (i = strlen("Near here "); i < padlen; i++)
			sprintf_append(msg, msglen, "-");

		sprintf_append(msg, msglen, "^\n");
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

void
format_source_context(char **msg, size_t *msglen, uc_source *src, size_t off, bool compact)
{
	size_t len, rlen;
	bool truncated;
	char buf[256];
	long srcpos;
	int eline;

	srcpos = ftell(src->fp);

	if (srcpos == -1)
		return;

	fseek(src->fp, 0, SEEK_SET);

	truncated = false;
	eline = 1;
	rlen = 0;

	while (fgets(buf, sizeof(buf), src->fp)) {
		len = strlen(buf);
		rlen += len;

		if (rlen > off) {
			if (compact)
				sprintf_append(msg, msglen, "\033[2;40;97m%17s  %s",
					source_filename(src, eline),
					truncated ? "..." : "");
			else
				sprintf_append(msg, msglen, "\n `%s",
					truncated ? "..." : "");

			format_context_line(msg, msglen, buf, len - (rlen - off) + (truncated ? 3 : 0), compact);
			break;
		}

		truncated = (len > 0 && buf[len-1] != '\n');
		eline += !truncated;
	}

	fseek(src->fp, srcpos, SEEK_SET);
}

void
format_error_context(char **msg, size_t *msglen, uc_source *src, json_object *stacktrace, size_t off)
{
	json_object *e, *fn, *file, *line, *byte;
	const char *path;
	size_t idx;

	for (idx = 0; idx < (stacktrace ? json_object_array_length(stacktrace) : 0); idx++) {
		e = json_object_array_get_idx(stacktrace, idx);
		fn = json_object_object_get(e, "function");
		file = json_object_object_get(e, "filename");

		if (idx == 0) {
			path = (file && strcmp(json_object_get_string(file), "[stdin]"))
				? json_object_get_string(file) : NULL;

			if (path && fn)
				sprintf_append(msg, msglen, "In %s(), file %s, ",
				               json_object_get_string(fn), path);
			else if (fn)
				sprintf_append(msg, msglen, "In %s(), ",
				               json_object_get_string(fn));
			else if (path)
				sprintf_append(msg, msglen, "In %s, ", path);
			else
				sprintf_append(msg, msglen, "In ");

			sprintf_append(msg, msglen, "line %" PRId64 ", byte %" PRId64 ":\n",
			               json_object_get_int64(json_object_object_get(e, "line")),
			               json_object_get_int64(json_object_object_get(e, "byte")));
		}
		else {
			line = json_object_object_get(e, "line");
			byte = json_object_object_get(e, "byte");

			sprintf_append(msg, msglen, "  called from %s%s (%s",
			               fn ? "function " : "anonymous function",
			               fn ? json_object_get_string(fn) : "",
			               file ? json_object_get_string(file) : "");

			if (line && byte)
				sprintf_append(msg, msglen, ":%" PRId64 ":%" PRId64 ")\n",
				               json_object_get_int64(line),
				               json_object_get_int64(byte));
			else
				sprintf_append(msg, msglen, "[C])\n");
		}
	}

	format_source_context(msg, msglen, src, off, false);
}

static double
uc_cast_double(json_object *v)
{
	enum json_type t;
	int64_t n;
	double d;

	t = uc_cast_number(v, &n, &d);
	errno = 0;

	if (t == json_type_double) {
		if (isnan(d))
			errno = EINVAL;
		else if (!isfinite(d))
			errno = EOVERFLOW;

		return d;
	}

	return (double)n;
}

static int64_t
uc_cast_int64(json_object *v)
{
	enum json_type t;
	int64_t n;
	double d;

	t = uc_cast_number(v, &n, &d);
	errno = 0;

	if (t == json_type_double) {
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

static json_object *
uc_print_common(uc_vm *vm, size_t nargs, FILE *fh)
{
	json_object *item;
	size_t reslen = 0;
	size_t len = 0;
	size_t arridx;
	const char *p;

	for (arridx = 0; arridx < nargs; arridx++) {
		item = uc_get_arg(arridx);

		if (json_object_is_type(item, json_type_string)) {
			p = json_object_get_string(item);
			len = json_object_get_string_len(item);
		}
		else {
			p = item ? json_object_get_string(item) : NULL;
			p = p ? p : "";
			len = strlen(p);
		}

		reslen += fwrite(p, 1, len, fh);
	}

	return xjs_new_int64(reslen);
}


static json_object *
uc_print(uc_vm *vm, size_t nargs)
{
	return uc_print_common(vm, nargs, stdout);
}

static json_object *
uc_length(uc_vm *vm, size_t nargs)
{
	json_object *arg = uc_get_arg(0);

	switch (json_object_get_type(arg)) {
	case json_type_object:
		return xjs_new_int64(json_object_object_length(arg));

	case json_type_array:
		return xjs_new_int64(json_object_array_length(arg));

	case json_type_string:
		return xjs_new_int64(json_object_get_string_len(arg));

	default:
		return NULL;
	}
}

static json_object *
uc_index(uc_vm *vm, size_t nargs, bool right)
{
	json_object *stack = uc_get_arg(0);
	json_object *needle = uc_get_arg(1);
	size_t arridx, len, ret = -1;
	const char *sstr, *nstr, *p;

	switch (json_object_get_type(stack)) {
	case json_type_array:
		for (arridx = 0, len = json_object_array_length(stack); arridx < len; arridx++) {
			if (uc_cmp(TK_EQ, json_object_array_get_idx(stack, arridx), needle)) {
				ret = arridx;

				if (!right)
					break;
			}
		}

		return xjs_new_int64(ret);

	case json_type_string:
		sstr = json_object_get_string(stack);
		nstr = needle ? json_object_get_string(needle) : NULL;
		len = needle ? strlen(nstr) : 0;

		for (p = sstr; *p && len; p++) {
			if (!strncmp(p, nstr, len)) {
				ret = p - sstr;

				if (!right)
					break;
			}
		}

		return xjs_new_int64(ret);

	default:
		return NULL;
	}
}

static json_object *
uc_lindex(uc_vm *vm, size_t nargs)
{
	return uc_index(vm, nargs, false);
}

static json_object *
uc_rindex(uc_vm *vm, size_t nargs)
{
	return uc_index(vm, nargs, true);
}

static json_object *
uc_push(uc_vm *vm, size_t nargs)
{
	json_object *arr = uc_get_arg(0);
	json_object *item = NULL;
	size_t arridx;

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	for (arridx = 1; arridx < nargs; arridx++) {
		item = uc_get_arg(arridx);
		json_object_array_add(arr, uc_value_get(item));
	}

	return uc_value_get(item);
}

static json_object *
uc_pop(uc_vm *vm, size_t nargs)
{
	json_object *arr = uc_get_arg(0);
	json_object *item = NULL;
	size_t arrlen;

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	arrlen = json_object_array_length(arr);

	if (arrlen > 0) {
		item = uc_value_get(json_object_array_get_idx(arr, arrlen - 1));
		json_object_array_del_idx(arr, arrlen - 1, 1);
#ifdef HAVE_ARRAY_SHRINK
		json_object_array_shrink(arr, 0);
#endif
	}

	return item;
}

static json_object *
uc_shift(uc_vm *vm, size_t nargs)
{
	json_object *arr = uc_get_arg(0);
	json_object *item = NULL;
	size_t arridx, arrlen;

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	item = uc_value_get(json_object_array_get_idx(arr, 0));
	arrlen = json_object_array_length(arr);

	for (arridx = 0; arridx < arrlen - 1; arridx++)
		json_object_array_put_idx(arr, arridx,
			uc_value_get(json_object_array_get_idx(arr, arridx + 1)));

	json_object_array_del_idx(arr, arrlen - 1, 1);
#ifdef HAVE_ARRAY_SHRINK
	json_object_array_shrink(arr, 0);
#endif

	return item;
}

static json_object *
uc_unshift(uc_vm *vm, size_t nargs)
{
	json_object *arr = uc_get_arg(0);
	json_object *item = NULL;
	size_t arridx, arrlen, addlen;

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	arrlen = json_object_array_length(arr);
	addlen = nargs - 1;

	for (arridx = arrlen; arridx > 0; arridx--)
		json_object_array_put_idx(arr, arridx + addlen - 1,
			uc_value_get(json_object_array_get_idx(arr, arridx - 1)));

	for (arridx = 0; arridx < addlen; arridx++) {
		item = uc_get_arg(arridx + 1);
		json_object_array_put_idx(arr, arridx, uc_value_get(item));
	}

	return uc_value_get(item);
}

static json_object *
uc_chr(uc_vm *vm, size_t nargs)
{
	size_t idx;
	int64_t n;
	char *str;

	if (!nargs)
		return xjs_new_string_len("", 0);

	str = xalloc(nargs);

	for (idx = 0; idx < nargs; idx++) {
		n = uc_cast_int64(uc_get_arg(idx));

		if (n < 0)
			n = 0;
		else if (n > 255)
			n = 255;

		str[idx] = (char)n;
	}

	return xjs_new_string_len(str, nargs);
}

static json_object *
uc_delete(uc_vm *vm, size_t nargs)
{
	json_object *obj = uc_get_arg(0);
	json_object *rv = NULL;
	const char *key;
	size_t arridx;

	if (!json_object_is_type(obj, json_type_object))
		return NULL;

	for (arridx = 1; arridx < nargs; arridx++) {
		uc_value_put(rv);

		key = json_object_get_string(uc_get_arg(arridx));
		rv = uc_value_get(json_object_object_get(obj, key ? key : "null"));

		json_object_object_del(obj, key ? key : "null");
	}

	return rv;
}

static json_object *
uc_die(uc_vm *vm, size_t nargs)
{
	const char *msg = json_object_get_string(uc_get_arg(0));

	uc_vm_raise_exception(vm, EXCEPTION_USER, msg ? msg : "Died");

	return NULL;
}

static json_object *
uc_exists(uc_vm *vm, size_t nargs)
{
	json_object *obj = uc_get_arg(0);
	const char *key = json_object_get_string(uc_get_arg(1));

	if (!json_object_is_type(obj, json_type_object))
		return false;

	return xjs_new_boolean(json_object_object_get_ex(obj, key ? key : "null", NULL));
}

__attribute__((noreturn)) static json_object *
uc_exit(uc_vm *vm, size_t nargs)
{
	int64_t n = uc_cast_int64(uc_get_arg(0));

	exit(n);
}

static json_object *
uc_getenv(uc_vm *vm, size_t nargs)
{
	const char *key = json_object_get_string(uc_get_arg(0));
	char *val = key ? getenv(key) : NULL;

	return val ? xjs_new_string(val) : NULL;
}

static json_object *
uc_filter(uc_vm *vm, size_t nargs)
{
	json_object *obj = uc_get_arg(0);
	json_object *func = uc_get_arg(1);
	json_object *rv, *arr;
	size_t arridx, arrlen;

	if (!json_object_is_type(obj, json_type_array))
		return NULL;

	arr = xjs_new_array();

	for (arrlen = json_object_array_length(obj), arridx = 0; arridx < arrlen; arridx++) {
		/* XXX: revisit leaks */
		uc_vm_stack_push(vm, uc_value_get(func));
		uc_vm_stack_push(vm, uc_value_get(json_object_array_get_idx(obj, arridx)));
		uc_vm_stack_push(vm, xjs_new_int64(arridx));
		uc_vm_stack_push(vm, uc_value_get(obj));

		if (uc_vm_call(vm, false, 3)) {
			uc_value_put(arr);

			return NULL;
		}

		rv = uc_vm_stack_pop(vm);

		if (uc_val_is_truish(rv))
			json_object_array_add(arr, uc_value_get(json_object_array_get_idx(obj, arridx)));

		uc_value_put(rv);
	}

	return arr;
}

static json_object *
uc_hex(uc_vm *vm, size_t nargs)
{
	const char *val = json_object_get_string(uc_get_arg(0));
	int64_t n;
	char *e;

	if (!val || !isxdigit(*val))
		return uc_double_new(NAN);

	n = strtoll(val, &e, 16);

	if (e == val || *e)
		return uc_double_new(NAN);

	return xjs_new_int64(n);
}

static json_object *
uc_int(uc_vm *vm, size_t nargs)
{
	int64_t n = uc_cast_int64(uc_get_arg(0));

	if (errno == EINVAL || errno == EOVERFLOW)
		return uc_double_new(NAN);

	return xjs_new_int64(n);
}

static json_object *
uc_join(uc_vm *vm, size_t nargs)
{
	const char *sep = json_object_get_string(uc_get_arg(0));
	json_object *arr = uc_get_arg(1);
	json_object *rv = NULL;
	size_t arrlen, arridx, len = 1;
	const char *item;
	char *res, *p;
	int ret;

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	for (arrlen = json_object_array_length(arr), arridx = 0; arridx < arrlen; arridx++) {
		if (arridx > 0)
			len += strlen(sep);

		item = json_object_get_string(json_object_array_get_idx(arr, arridx));
		len += item ? strlen(item) : 0;
	}

	p = res = xalloc(len);

	for (arrlen = json_object_array_length(arr), arridx = 0; arridx < arrlen; arridx++) {
		if (arridx > 0) {
			ret = snprintf(p, len, "%s", sep);

			if (ret < 0 || ret >= len)
				goto out;

			len -= ret;
			p += ret;
		}

		item = json_object_get_string(json_object_array_get_idx(arr, arridx));

		if (item) {
			ret = snprintf(p, len, "%s", item);

			if (ret < 0 || ret >= len)
				goto out;

			len -= ret;
			p += ret;
		}
	}

	rv = xjs_new_string(res);

out:
	free(res);

	return rv;
}

static json_object *
uc_keys(uc_vm *vm, size_t nargs)
{
	json_object *obj = uc_get_arg(0);
	json_object *arr = NULL;

	if (!json_object_is_type(obj, json_type_object))
		return NULL;

	arr = xjs_new_array();

	json_object_object_foreach(obj, key, val)
		json_object_array_add(arr, xjs_new_string(key));

	return arr;
}

static json_object *
uc_lc(uc_vm *vm, size_t nargs)
{
	const char *str = json_object_get_string(uc_get_arg(0));
	size_t len = str ? strlen(str) : 0;
	json_object *rv = NULL;
	char *res, *p;

	if (!str)
		return NULL;

	res = p = xalloc(len);

	while (*str)
		if (*str >= 'A' && *str <= 'Z')
			*p++ = 32 + *str++;
		else
			*p++ = *str++;

	rv = xjs_new_string_len(res, len);
	free(res);

	return rv;
}

static json_object *
uc_map(uc_vm *vm, size_t nargs)
{
	json_object *obj = uc_get_arg(0);
	json_object *func = uc_get_arg(1);
	json_object *arr, *rv;
	size_t arridx, arrlen;

	if (!json_object_is_type(obj, json_type_array))
		return NULL;

	arr = xjs_new_array();

	for (arrlen = json_object_array_length(obj), arridx = 0; arridx < arrlen; arridx++) {
		/* XXX: revisit leaks */
		uc_vm_stack_push(vm, uc_value_get(func));
		uc_vm_stack_push(vm, uc_value_get(json_object_array_get_idx(obj, arridx)));
		uc_vm_stack_push(vm, xjs_new_int64(arridx));
		uc_vm_stack_push(vm, uc_value_get(obj));

		if (uc_vm_call(vm, false, 3)) {
			uc_value_put(arr);

			return NULL;
		}

		rv = uc_vm_stack_pop(vm);

		json_object_array_add(arr, rv);
	}

	return arr;
}

static json_object *
uc_ord(uc_vm *vm, size_t nargs)
{
	json_object *obj = uc_get_arg(0);
	json_object *rv, *pos;
	const char *str;
	size_t i, len;
	int64_t n;

	if (!json_object_is_type(obj, json_type_string))
		return NULL;

	str = json_object_get_string(obj);
	len = json_object_get_string_len(obj);

	if (nargs == 1)
		return str[0] ? xjs_new_int64((int64_t)str[0]) : NULL;

	rv = xjs_new_array();

	for (i = 1; i < nargs; i++) {
		pos = uc_get_arg(i);

		if (json_object_is_type(pos, json_type_int)) {
			n = json_object_get_int64(pos);

			if (n < 0)
				n += len;

			if (n >= 0 && n < len) {
				json_object_array_add(rv, xjs_new_int64((int64_t)str[n]));
				continue;
			}
		}

		json_object_array_add(rv, NULL);
	}

	return rv;
}

static json_object *
uc_type(uc_vm *vm, size_t nargs)
{
	json_object *v = uc_get_arg(0);
	uc_objtype_t o = uc_object_type(v);

	switch (o) {
	case UC_OBJ_CFUNCTION:
	case UC_OBJ_FUNCTION:
	case UC_OBJ_CLOSURE:
		return xjs_new_string("function");

	case UC_OBJ_RESSOURCE:
		return xjs_new_string("ressource");

	default:
		switch (json_object_get_type(v)) {
		case json_type_object:
			return xjs_new_string("object");

		case json_type_array:
			return xjs_new_string("array");

		case json_type_double:
			return xjs_new_string("double");

		case json_type_int:
			return xjs_new_string("int");

		case json_type_boolean:
			return xjs_new_string("bool");

		case json_type_string:
			return xjs_new_string("string");

		default:
			return NULL;
		}
	}
}

static json_object *
uc_reverse(uc_vm *vm, size_t nargs)
{
	json_object *obj = uc_get_arg(0);
	json_object *rv = NULL;
	size_t len, arridx;
	const char *str;
	char *dup, *p;

	if (json_object_is_type(obj, json_type_array)) {
		rv = xjs_new_array();

		for (arridx = json_object_array_length(obj); arridx > 0; arridx--)
			json_object_array_add(rv, uc_value_get(json_object_array_get_idx(obj, arridx - 1)));
	}
	else if (json_object_is_type(obj, json_type_string)) {
		len = json_object_get_string_len(obj);
		str = json_object_get_string(obj);
		p = dup = xalloc(len + 1);

		while (len > 0)
			*p++ = str[--len];

		rv = xjs_new_string(dup);

		free(dup);
	}

	return rv;
}


static struct {
	uc_vm *vm;
	bool ex;
	json_object *fn;
} sort_ctx;

static int
sort_fn(const void *k1, const void *k2)
{
	json_object * const *v1 = k1;
	json_object * const *v2 = k2;
	json_object *rv;
	int ret;

	if (!sort_ctx.fn)
		return !uc_cmp(TK_LT, *v1, *v2);

	if (sort_ctx.ex)
		return 0;

	uc_vm_stack_push(sort_ctx.vm, uc_value_get(sort_ctx.fn));
	uc_vm_stack_push(sort_ctx.vm, uc_value_get(*v1));
	uc_vm_stack_push(sort_ctx.vm, uc_value_get(*v2));

	if (uc_vm_call(sort_ctx.vm, false, 2)) {
		sort_ctx.ex = true;

		return 0;
	}

	rv = uc_vm_stack_pop(sort_ctx.vm);

	ret = !uc_val_is_truish(rv);

	uc_value_put(rv);

	return ret;
}

static json_object *
uc_sort(uc_vm *vm, size_t nargs)
{
	json_object *arr = uc_get_arg(0);
	json_object *fn = uc_get_arg(1);

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	sort_ctx.vm = vm;
	sort_ctx.fn = fn;

	json_object_array_sort(arr, sort_fn);

	return sort_ctx.ex ? NULL : uc_value_get(arr);
}

static json_object *
uc_splice(uc_vm *vm, size_t nargs)
{
	json_object *arr = uc_get_arg(0);
	int64_t ofs = uc_cast_int64(uc_get_arg(1));
	int64_t remlen = uc_cast_int64(uc_get_arg(2));
	size_t arrlen, addlen, idx;

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	arrlen = json_object_array_length(arr);
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
		else if (ofs > arrlen) {
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
		else if (ofs > arrlen) {
			ofs = arrlen;
		}

		if (remlen < 0) {
			remlen = arrlen - ofs + remlen;

			if (remlen < 0)
				remlen = 0;
		}
		else if (remlen > arrlen - ofs) {
			remlen = arrlen - ofs;
		}

		addlen -= 3;
	}

	if (addlen < remlen) {
		json_object_array_del_idx(arr, ofs, remlen - addlen);
	}
	else if (addlen > remlen) {
		for (idx = arrlen; idx > ofs; idx--)
			json_object_array_put_idx(arr, idx + addlen - remlen - 1,
				uc_value_get(json_object_array_get_idx(arr, idx - 1)));
	}

	for (idx = 0; idx < addlen; idx++)
		json_object_array_put_idx(arr, ofs + idx,
			uc_value_get(uc_get_arg(3 + idx)));

	return uc_value_get(arr);
}

static json_object *
uc_split(uc_vm *vm, size_t nargs)
{
	json_object *str = uc_get_arg(0);
	json_object *sep = uc_get_arg(1);
	json_object *arr = NULL;
	const char *p, *sepstr, *splitstr;
	int eflags = 0, res;
	regmatch_t pmatch;
	uc_regexp *re;
	size_t seplen;

	if (!sep || !json_object_is_type(str, json_type_string))
		return NULL;

	arr = xjs_new_array();
	splitstr = json_object_get_string(str);

	if (uc_object_is_type(sep, UC_OBJ_REGEXP)) {
		re = uc_object_as_regexp(sep);

		while (true) {
			res = regexec(&re->re, splitstr, 1, &pmatch, eflags);

			if (res == REG_NOMATCH)
				break;

			json_object_array_add(arr, xjs_new_string_len(splitstr, pmatch.rm_so));

			splitstr += pmatch.rm_eo;
			eflags |= REG_NOTBOL;
		}

		json_object_array_add(arr, xjs_new_string(splitstr));
	}
	else if (json_object_is_type(sep, json_type_string)) {
		sepstr = json_object_get_string(sep);

		for (p = splitstr + (*sepstr ? 1 : 0), seplen = strlen(sepstr); *p; p++) {
			if (!strncmp(p, sepstr, seplen)) {
				if (*sepstr || p > splitstr)
					json_object_array_add(arr, xjs_new_string_len(splitstr, p - splitstr));

				splitstr = p + seplen;
				p = splitstr - (*sepstr ? 1 : 0);
			}
		}

		if (*splitstr)
			json_object_array_add(arr, xjs_new_string_len(splitstr, p - splitstr));
	}
	else {
		uc_value_put(arr);

		return NULL;
	}

	return arr;
}

static json_object *
uc_substr(uc_vm *vm, size_t nargs)
{
	json_object *str = uc_get_arg(0);
	int64_t ofs = uc_cast_int64(uc_get_arg(1));
	int64_t sublen = uc_cast_int64(uc_get_arg(2));
	const char *p;
	size_t len;

	if (!json_object_is_type(str, json_type_string))
		return NULL;

	p = json_object_get_string(str);
	len = json_object_get_string_len(str);

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
		else if (ofs > len) {
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
		else if (ofs > len) {
			ofs = len;
		}

		if (sublen < 0) {
			sublen = len - ofs + sublen;

			if (sublen < 0)
				sublen = 0;
		}
		else if (sublen > len - ofs) {
			sublen = len - ofs;
		}

		break;
	}

	return xjs_new_string_len(p + ofs, sublen);
}

static json_object *
uc_time(uc_vm *vm, size_t nargs)
{
	time_t t = time(NULL);

	return xjs_new_int64((int64_t)t);
}

static json_object *
uc_uc(uc_vm *vm, size_t nargs)
{
	const char *str = json_object_get_string(uc_get_arg(0));
	size_t len = str ? strlen(str) : 0;
	json_object *rv = NULL;
	char *res, *p;

	if (!str)
		return NULL;

	res = p = xalloc(len);

	while (*str)
		if (*str >= 'a' && *str <= 'z')
			*p++ = *str++ - 32;
		else
			*p++ = *str++;

	rv = xjs_new_string_len(res, len);
	free(res);

	return rv;
}

static json_object *
uc_uchr(uc_vm *vm, size_t nargs)
{
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

	return xjs_new_string_len(str, ulen);
}

static json_object *
uc_values(uc_vm *vm, size_t nargs)
{
	json_object *obj = uc_get_arg(0);
	json_object *arr;

	if (!json_object_is_type(obj, json_type_object))
		return NULL;

	arr = xjs_new_array();

	json_object_object_foreach(obj, key, val) {
		(void)key;
		json_object_array_add(arr, uc_value_get(val));
	}

	return arr;
}

static json_object *
uc_trim_common(uc_vm *vm, size_t nargs, bool start, bool end)
{
	json_object *str = uc_get_arg(0);
	json_object *chr = uc_get_arg(1);
	const char *p, *c;
	size_t len;

	if (!json_object_is_type(str, json_type_string) ||
		(chr != NULL && !json_object_is_type(chr, json_type_string)))
		return NULL;

	c = json_object_get_string(chr);
	c = c ? c : " \t\r\n";

	p = json_object_get_string(str);
	len = json_object_get_string_len(str);

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

	return xjs_new_string_len(p, len);
}

static json_object *
uc_trim(uc_vm *vm, size_t nargs)
{
	return uc_trim_common(vm, nargs, true, true);
}

static json_object *
uc_ltrim(uc_vm *vm, size_t nargs)
{
	return uc_trim_common(vm, nargs, true, false);
}

static json_object *
uc_rtrim(uc_vm *vm, size_t nargs)
{
	return uc_trim_common(vm, nargs, false, true);
}

static size_t
uc_printf_common(uc_vm *vm, size_t nargs, char **res)
{
	json_object *fmt = uc_get_arg(0);
	char *fp, sfmt[sizeof("%0- 123456789.123456789%")];
	union { const char *s; int64_t n; double d; } arg;
	const char *fstr, *last, *p;
	size_t len = 0, argidx = 1;
	enum json_type t;

	*res = NULL;

	if (json_object_is_type(fmt, json_type_string))
		fstr = json_object_get_string(fmt);
	else
		fstr = "";

	for (last = p = fstr; *p; p++) {
		if (*p == '%') {
			snprintf_append(res, &len, "%s", p - last, last);

			last = p++;

			fp = sfmt;
			*fp++ = '%';

			memset(&arg, 0, sizeof(arg));

			while (strchr("0- ", *p)) {
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
				t = json_type_int;

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
				t = json_type_double;

				if (argidx < nargs)
					arg.d = uc_cast_double(uc_get_arg(argidx++));
				else
					arg.d = 0;

				break;

			case 'c':
				t = json_type_int;

				if (argidx < nargs)
					arg.n = uc_cast_int64(uc_get_arg(argidx++)) & 0xff;
				else
					arg.n = 0;

				break;

			case 's':
				t = json_type_string;

				if (argidx < nargs)
					arg.s = json_object_get_string(uc_get_arg(argidx++));
				else
					arg.s = NULL;

				arg.s = arg.s ? arg.s : "(null)";

				break;

			case 'J':
				t = json_type_string;

				if (argidx < nargs)
					arg.s = json_object_to_json_string_ext(
						uc_get_arg(argidx++),
						JSON_C_TO_STRING_SPACED|JSON_C_TO_STRING_NOSLASHESCAPE|JSON_C_TO_STRING_STRICT);
				else
					arg.s = NULL;

				arg.s = arg.s ? arg.s : "null";

				break;

			case '%':
				t = json_type_null;

				break;

			default:
				goto next;
			}

			if (fp + 2 >= sfmt + sizeof(sfmt))
				goto next;

			*fp++ = (t == json_type_string) ? 's' : *p;
			*fp = 0;

#pragma GCC diagnostic ignored "-Wformat-security"

			switch (t) {
			case json_type_int:    sprintf_append(res, &len, sfmt, arg.n); break;
			case json_type_double: sprintf_append(res, &len, sfmt, arg.d); break;
			case json_type_string: sprintf_append(res, &len, sfmt, arg.s); break;
			default:               sprintf_append(res, &len, sfmt);        break;
			}

#pragma GCC diagnostic pop

			last = p + 1;

next:
			continue;
		}
	}

	snprintf_append(res, &len, "%s", p - last, last);

	return len;
}

static json_object *
uc_sprintf(uc_vm *vm, size_t nargs)
{
	json_object *rv;
	char *str = NULL;
	size_t len;

	len = uc_printf_common(vm, nargs, &str);
	rv = xjs_new_string_len(str, len);

	free(str);

	return rv;
}

static json_object *
uc_printf(uc_vm *vm, size_t nargs)
{
	char *str = NULL;
	size_t len;

	len = uc_printf_common(vm, nargs, &str);
	len = fwrite(str, 1, len, stdout);

	free(str);

	return xjs_new_int64(len);
}

static bool
uc_require_so(uc_vm *vm, const char *path, json_object **res)
{
	void (*init)(const uc_ops *, uc_prototype *);
	uc_prototype *scope;
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

	init = dlsym(dlh, "uc_module_entry");

	if (!init) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Module '%s' provides no 'uc_module_entry' function", path);

		return true;
	}

	scope = uc_prototype_new(NULL);

	init(&uc, scope);

	*res = scope->header.jso;

	return true;
}

static bool
uc_require_ucode(uc_vm *vm, const char *path, uc_prototype *scope, json_object **res)
{
	uc_exception_type_t extype;
	uc_prototype *prev_scope;
	uc_function *function;
	uc_closure *closure;
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

	closure = uc_closure_new(function, false);

	uc_vm_stack_push(vm, closure->header.jso);

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
uc_require_path(uc_vm *vm, const char *path_template, const char *name, json_object **res)
{
	const char *p, *q, *last;
	char *path = NULL;
	size_t plen = 0;
	bool rv = false;

	*res = NULL;

	p = strchr(path_template, '*');

	if (!p)
		goto invalid;

	snprintf_append(&path, &plen, "%s", p - path_template, path_template);

	for (q = last = name;; q++) {
		if (*q == '.' || *q == '\0') {
			snprintf_append(&path, &plen, "%s", q - last, last);
			sprintf_append(&path, &plen, "%s", *q ? "/" : ++p);

			if (*q == '\0')
				break;

			last = q + 1;
		}
		else if (!isalnum(*q) && *q != '_') {
			goto invalid;
		}
	}

	if (!strcmp(p, ".so"))
		rv = uc_require_so(vm, path, res);
	else if (!strcmp(p, ".uc"))
		rv = uc_require_ucode(vm, path, NULL, res);

invalid:
	free(path);

	return rv;
}

static json_object *
uc_require(uc_vm *vm, size_t nargs)
{
	const char *name = json_object_get_string(uc_get_arg(0));

	json_object *val = uc_get_arg(0);
	json_object *search, *se, *res;
	size_t arridx, arrlen;

	if (!json_object_is_type(val, json_type_string))
		return NULL;

	name = json_object_get_string(val);
	search = uc_prototype_lookup(vm->globals, "REQUIRE_SEARCH_PATH");

	if (!json_object_is_type(search, json_type_array)) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Global require search path not set");

		return NULL;
	}

	for (arridx = 0, arrlen = json_object_array_length(search); arridx < arrlen; arridx++) {
		se = json_object_array_get_idx(search, arridx);

		if (!json_object_is_type(se, json_type_string))
			continue;

		if (uc_require_path(vm, json_object_get_string(se), name, &res))
			return res;
	}

	uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
	                      "No module named '%s' could be found", name);

	return NULL;
}

static json_object *
uc_iptoarr(uc_vm *vm, size_t nargs)
{
	json_object *ip = uc_get_arg(0);
	json_object *res;
	union {
		uint8_t u8[4];
		struct in_addr in;
		struct in6_addr in6;
	} a;
	int i;

	if (!json_object_is_type(ip, json_type_string))
		return NULL;

	if (inet_pton(AF_INET6, json_object_get_string(ip), &a)) {
		res = xjs_new_array();

		for (i = 0; i < 16; i++)
			json_object_array_add(res, xjs_new_int64(a.in6.s6_addr[i]));

		return res;
	}
	else if (inet_pton(AF_INET, json_object_get_string(ip), &a)) {
		res = xjs_new_array();

		json_object_array_add(res, xjs_new_int64(a.u8[0]));
		json_object_array_add(res, xjs_new_int64(a.u8[1]));
		json_object_array_add(res, xjs_new_int64(a.u8[2]));
		json_object_array_add(res, xjs_new_int64(a.u8[3]));

		return res;
	}

	return NULL;
}

static int
check_byte(json_object *v)
{
	int n;

	if (!json_object_is_type(v, json_type_int))
		return -1;

	n = json_object_get_int(v);

	if (n < 0 || n > 255)
		return -1;

	return n;
}

static json_object *
uc_arrtoip(uc_vm *vm, size_t nargs)
{
	json_object *arr = uc_get_arg(0);
	union {
		uint8_t u8[4];
		struct in6_addr in6;
	} a;
	char buf[INET6_ADDRSTRLEN];
	int i, n;

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	switch (json_object_array_length(arr)) {
	case 4:
		for (i = 0; i < 4; i++) {
			n = check_byte(json_object_array_get_idx(arr, i));

			if (n < 0)
				return NULL;

			a.u8[i] = n;
		}

		inet_ntop(AF_INET, &a, buf, sizeof(buf));

		return xjs_new_string(buf);

	case 16:
		for (i = 0; i < 16; i++) {
			n = check_byte(json_object_array_get_idx(arr, i));

			if (n < 0)
				return NULL;

			a.in6.s6_addr[i] = n;
		}

		inet_ntop(AF_INET6, &a, buf, sizeof(buf));

		return xjs_new_string(buf);

	default:
		return NULL;
	}
}

static json_object *
uc_match(uc_vm *vm, size_t nargs)
{
	json_object *subject = uc_get_arg(0);
	json_object *pattern = uc_get_arg(1);
	json_object *rv = NULL, *m;
	int eflags = 0, res, i;
	regmatch_t pmatch[10];
	uc_regexp *re;
	const char *p;

	if (!uc_object_is_type(pattern, UC_OBJ_REGEXP) || !subject)
		return NULL;

	p = json_object_get_string(subject);
	re = uc_object_as_regexp(pattern);

	while (true) {
		res = regexec(&re->re, p, ARRAY_SIZE(pmatch), pmatch, eflags);

		if (res == REG_NOMATCH)
			break;

		m = xjs_new_array();

		for (i = 0; i < ARRAY_SIZE(pmatch) && pmatch[i].rm_so != -1; i++) {
			json_object_array_add(m,
				xjs_new_string_len(p + pmatch[i].rm_so,
				                   pmatch[i].rm_eo - pmatch[i].rm_so));
		}

		if (re->global) {
			if (!rv)
				rv = xjs_new_array();

			json_object_array_add(rv, m);

			p += pmatch[0].rm_eo;
			eflags |= REG_NOTBOL;
		}
		else {
			rv = m;
			break;
		}
	}

	return rv;
}

static json_object *
uc_replace_cb(uc_vm *vm, json_object *func,
              const char *subject, regmatch_t *pmatch, size_t plen,
              char **sp, size_t *sl)
{
	json_object *rv;
	size_t i;

	/* XXX: revisit leaks */
	uc_vm_stack_push(vm, uc_value_get(func));

	for (i = 0; i < plen && pmatch[i].rm_so != -1; i++) {
		uc_vm_stack_push(vm,
			xjs_new_string_len(subject + pmatch[i].rm_so,
			                   pmatch[i].rm_eo - pmatch[i].rm_so));
	}

	if (uc_vm_call(vm, false, i))
		return NULL;

	rv = uc_vm_stack_pop(vm);

	sprintf_append(sp, sl, "%s", rv ? json_object_get_string(rv) : "null");

	uc_value_put(rv);

	return NULL;
}

static void
uc_replace_str(uc_vm *vm, json_object *str,
               const char *subject, regmatch_t *pmatch, size_t plen,
               char **sp, size_t *sl)
{
	const char *r = str ? json_object_get_string(str) : "null";
	const char *p = r;
	bool esc = false;
	int i;

	for (p = r; *p; p++) {
		if (esc) {
			switch (*p) {
			case '&':
				if (pmatch[0].rm_so != -1)
					snprintf_append(sp, sl, "%s", pmatch[0].rm_eo - pmatch[0].rm_so,
					                subject + pmatch[0].rm_so);
				break;

			case '`':
				if (pmatch[0].rm_so != -1)
					snprintf_append(sp, sl, "%s", pmatch[0].rm_so, subject);
				break;

			case '\'':
				if (pmatch[0].rm_so != -1)
					sprintf_append(sp, sl, "%s", subject + pmatch[0].rm_eo);
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
				if (i < plen && pmatch[i].rm_so != -1)
					snprintf_append(sp, sl, "%s", pmatch[i].rm_eo - pmatch[i].rm_so,
					                subject + pmatch[i].rm_so);
				else
					sprintf_append(sp, sl, "$%c", *p);
				break;

			case '$':
				sprintf_append(sp, sl, "$");
				break;

			default:
				sprintf_append(sp, sl, "$%c", *p);
			}

			esc = false;
		}
		else if (*p == '$') {
			esc = true;
		}
		else {
			sprintf_append(sp, sl, "%c", *p);
		}
	}
}

static json_object *
uc_replace(uc_vm *vm, size_t nargs)
{
	json_object *subject = uc_get_arg(0);
	json_object *pattern = uc_get_arg(1);
	json_object *replace = uc_get_arg(2);
	json_object *rv = NULL;
	const char *sb, *p, *l;
	regmatch_t pmatch[10];
	int eflags = 0, res;
	size_t sl = 0, pl;
	char *sp = NULL;
	uc_regexp *re;

	if (!pattern || !subject || !replace)
		return NULL;

	if (uc_object_is_type(pattern, UC_OBJ_REGEXP)) {
		p = json_object_get_string(subject);
		re = uc_object_as_regexp(pattern);

		while (true) {
			res = regexec(&re->re, p, ARRAY_SIZE(pmatch), pmatch, eflags);

			if (res == REG_NOMATCH)
				break;

			snprintf_append(&sp, &sl, "%s", pmatch[0].rm_so, p);

			if (uc_object_is_callable(replace)) {
				rv = uc_replace_cb(vm, replace, p, pmatch, ARRAY_SIZE(pmatch), &sp, &sl);

				if (rv) {
					free(sp);

					return rv;
				}
			}
			else {
				uc_replace_str(vm, replace, p, pmatch, ARRAY_SIZE(pmatch), &sp, &sl);
			}

			p += pmatch[0].rm_eo;

			if (re->global)
				eflags |= REG_NOTBOL;
			else
				break;
		}

		sprintf_append(&sp, &sl, "%s", p);
	}
	else {
		sb = json_object_get_string(subject);
		p = json_object_get_string(pattern);
		pl = strlen(p);

		for (l = sb; *sb; sb++) {
			if (!strncmp(sb, p, pl)) {
				snprintf_append(&sp, &sl, "%s", sb - l, l);

				pmatch[0].rm_so = sb - l;
				pmatch[0].rm_eo = pmatch[0].rm_so + pl;

				if (uc_object_is_callable(replace)) {
					rv = uc_replace_cb(vm, replace, l, pmatch, 1, &sp, &sl);

					if (rv) {
						free(sp);

						return rv;
					}
				}
				else {
					uc_replace_str(vm, replace, l, pmatch, 1, &sp, &sl);
				}

				l = sb + pl;
				sb += pl - 1;
			}
		}

		sprintf_append(&sp, &sl, "%s", l);
	}

	rv = xjs_new_string_len(sp, sl);
	free(sp);

	return rv;
}

static json_object *
uc_json(uc_vm *vm, size_t nargs)
{
	json_object *rv, *src = uc_get_arg(0);
	struct json_tokener *tok = NULL;
	enum json_tokener_error err;
	const char *str;
	size_t len;

	if (!json_object_is_type(src, json_type_string)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
		                      "Passed value is not a string");

		return NULL;
	}

	tok = xjs_new_tokener();
	str = json_object_get_string(src);
	len = json_object_get_string_len(src);

	rv = json_tokener_parse_ex(tok, str, len);
	err = json_tokener_get_error(tok);

	if (err == json_tokener_continue) {
		uc_value_put(rv);
		uc_vm_raise_exception(vm, EXCEPTION_SYNTAX,
		                      "Unexpected end of string in JSON data");

		return NULL;
	}
	else if (err != json_tokener_success) {
		uc_value_put(rv);
		uc_vm_raise_exception(vm, EXCEPTION_SYNTAX,
		                      "Failed to parse JSON string: %s",
		                      json_tokener_error_desc(err));

		return NULL;
	}
	else if (json_tokener_get_parse_end(tok) < len) {
		uc_value_put(rv);
		uc_vm_raise_exception(vm, EXCEPTION_SYNTAX,
		                      "Trailing garbage after JSON data");

		return NULL;
	}

	json_tokener_free(tok);

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

static json_object *
uc_include(uc_vm *vm, size_t nargs)
{
	json_object *path = uc_get_arg(0);
	json_object *scope = uc_get_arg(1);
	json_object *rv = NULL;
	uc_closure *closure = NULL;
	uc_prototype *sc;
	bool put = false;
	size_t i;
	char *p;

	if (!json_object_is_type(path, json_type_string)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
		                      "Passed filename is not a string");

		return NULL;
	}

	if (scope && !json_object_is_type(scope, json_type_object)) {
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

	p = include_path(closure->function->source->filename, json_object_get_string(path));

	if (!p) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Include file not found");

		return NULL;
	}

	if (uc_object_is_type(scope, UC_OBJ_PROTOTYPE)) {
		sc = uc_object_as_prototype(scope);
	}
	else if (scope) {
		sc = uc_prototype_new(vm->globals);
		put = true;

		json_object_object_foreach(scope, key, val)
			json_object_object_add(sc->header.jso, key, uc_value_get(val));
	}
	else {
		sc = vm->globals;
	}

	if (uc_require_ucode(vm, p, sc, &rv))
		uc_value_put(rv);

	free(p);

	if (put)
		uc_value_put(sc->header.jso);

	return NULL;
}

static json_object *
uc_warn(uc_vm *vm, size_t nargs)
{
	return uc_print_common(vm, nargs, stderr);
}

static json_object *
uc_system(uc_vm *vm, size_t nargs)
{
	json_object *cmdline = uc_get_arg(0);
	json_object *timeout = uc_get_arg(1);
	sigset_t sigmask, sigomask;
	const char **arglist, *fn;
	struct timespec ts;
	int64_t tms;
	pid_t cld;
	size_t i;
	int rc;

	switch (json_object_get_type(cmdline)) {
	case json_type_string:
		arglist = xalloc(sizeof(*arglist) * 4);
		arglist[0] = "/bin/sh";
		arglist[1] = "-c";
		arglist[2] = json_object_get_string(cmdline);
		arglist[3] = NULL;
		break;

	case json_type_array:
		arglist = xalloc(sizeof(*arglist) * (json_object_array_length(cmdline) + 1));

		for (i = 0; i < json_object_array_length(cmdline); i++)
			arglist[i] = json_object_get_string(json_object_array_get_idx(cmdline, i));

		arglist[i] = NULL;

		break;

	default:
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
		                      "Passed command is neither string nor array");

		return NULL;
	}

	if (timeout && (!json_object_is_type(timeout, json_type_int) || json_object_get_int64(timeout) < 0)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
		                      "Invalid timeout specified");

		return NULL;
	}

	tms = timeout ? json_object_get_int64(timeout) : 0;

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

		free(arglist);

		if (WIFEXITED(rc))
			return xjs_new_int64(WEXITSTATUS(rc));
		else if (WIFSIGNALED(rc))
			return xjs_new_int64(-WTERMSIG(rc));
		else if (WIFSTOPPED(rc))
			return xjs_new_int64(-WSTOPSIG(rc));

		return NULL;
	}

fail:
	if (tms > 0)
		sigprocmask(SIG_SETMASK, &sigomask, NULL);

	free(arglist);

	uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
	                      "%s(): %s", fn, strerror(errno));

	return NULL;
}

static json_object *
uc_trace(uc_vm *vm, size_t nargs)
{
	json_object *level = uc_get_arg(0);
	uint8_t prev_level;

	if (!json_object_is_type(level, json_type_int)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Invalid level specified");

		return NULL;
	}

	prev_level = vm->trace;
	vm->trace = json_object_get_int64(level);

	return xjs_new_int64(prev_level);
}

static json_object *
uc_proto(uc_vm *vm, size_t nargs)
{
	json_object *val = uc_get_arg(0);
	json_object *proto = NULL;
	uc_prototype *p, *ref;

	if (nargs < 2) {
		switch (uc_object_type(val)) {
		case UC_OBJ_PROTOTYPE:
			p = uc_object_as_prototype(val)->parent;

			return p ? uc_value_get(p->header.jso) : NULL;

		case UC_OBJ_RESSOURCE:
			p = uc_ressource_prototype(val);

			return p ? uc_value_get(p->header.jso) : NULL;

		default:
			return NULL;
		}
	}

	proto = uc_get_arg(1);

	switch (uc_object_type(proto)) {
	case UC_OBJ_PROTOTYPE:
		p = uc_object_as_prototype(proto);
		break;

	case UC_OBJ_RESSOURCE:
		p = uc_ressource_prototype(proto);
		break;

	default:
		switch (json_object_get_type(proto)) {
		case json_type_object:
			p = uc_protoref_new(proto, NULL);
			break;

		default:
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Passed value is neither a prototype, ressource or object");

			return NULL;
		}
	}

	ref = uc_protoref_new(val, p);

	return ref ? uc_value_get(ref->header.jso) : NULL;
}

static const uc_cfunction_list functions[] = {
	{ "chr",		uc_chr },
	{ "delete",		uc_delete },
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
	{ "proto",		uc_proto }
};


void
uc_lib_init(uc_prototype *scope)
{
	uc_add_proto_functions(scope, functions);
}
