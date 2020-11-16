/*
 * Copyright (C) 2020 Jo-Philipp Wich <jo@mein.io>
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

#include "ast.h"
#include "parser.h"
#include "lexer.h"
#include "eval.h"
#include "lib.h"
#include "module.h"

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
format_context_line(char **msg, size_t *msglen, const char *line, size_t off)
{
	const char *p;
	int padlen, i;

	for (p = line, padlen = 0; *p != '\n' && *p != '\0'; p++) {
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

static void
format_error_context(char **msg, size_t *msglen, struct ut_source *src, struct json_object *stacktrace, size_t off)
{
	struct json_object *e, *fn, *file, *line, *byte;
	size_t len, rlen, idx;
	const char *path;
	bool truncated;
	char buf[256];
	int eline;

	for (idx = 0; idx < json_object_array_length(stacktrace); idx++) {
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
			               json_object_get_string(file));

			if (line && byte)
				sprintf_append(msg, msglen, ":%" PRId64 ":%" PRId64 ")\n",
				               json_object_get_int64(line),
				               json_object_get_int64(byte));
			else
				sprintf_append(msg, msglen, " [C])\n");
		}
	}

	fseek(src->fp, 0, SEEK_SET);

	truncated = false;
	eline = 1;
	rlen = 0;

	while (fgets(buf, sizeof(buf), src->fp)) {
		len = strlen(buf);
		rlen += len;

		if (rlen > off) {
			sprintf_append(msg, msglen, "\n `%s", truncated ? "..." : "");
			format_context_line(msg, msglen, buf, len - (rlen - off) + (truncated ? 3 : 0));
			break;
		}

		truncated = (len > 0 && buf[len-1] != '\n');
		eline += !truncated;
	}
}

struct json_object *
ut_parse_error(struct ut_state *s, uint32_t off, uint64_t *tokens, int max_token)
{
	struct ut_op *op = ut_get_op(s, off);
	struct json_object *rv;
	size_t msglen = 0;
	bool first = true;
	char *msg = NULL;
	int i;

	for (i = 0; i <= max_token; i++) {
		if (tokens[i / 64] & ((uint64_t)1 << (i % 64))) {
			if (first) {
				sprintf_append(&msg, &msglen, "Expecting %s", ut_get_tokenname(i));
				first = false;
			}
			else if (i < max_token) {
				sprintf_append(&msg, &msglen, ", %s", ut_get_tokenname(i));
			}
			else {
				sprintf_append(&msg, &msglen, " or %s", ut_get_tokenname(i));
			}
		}
	}

	rv = ut_new_exception(s,
	                      op ? op->off : s->lex.lastoff,
	                      "Syntax error: Unexpected token\n%s", msg);
	free(msg);

	return rv;
}

char *
ut_format_error(struct ut_state *state, FILE *fp)
{
	struct ut_source *src;
	struct ut_op *tag;
	size_t msglen = 0;
	char *msg = NULL;

	tag = json_object_get_userdata(state->exception);
	src = tag->tag.data;

	sprintf_append(&msg, &msglen, "%s\n",
	               json_object_get_string(json_object_object_get(state->exception, "message")));

	if (tag->off)
		format_error_context(&msg, &msglen, src,
		                     json_object_object_get(state->exception, "stacktrace"),
		                     tag->off);

	return msg;
}

static double
ut_cast_double(struct json_object *v)
{
	enum json_type t;
	int64_t n;
	double d;

	t = ut_cast_number(v, &n, &d);
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
ut_cast_int64(struct json_object *v)
{
	enum json_type t;
	int64_t n;
	double d;

	t = ut_cast_number(v, &n, &d);
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

static int
ut_c_fn_to_string(struct json_object *v, struct printbuf *pb, int level, int flags)
{
	struct ut_op *op = json_object_get_userdata(v);
	struct ut_function *fn = (void *)op + ALIGN(sizeof(*op));

	return sprintbuf(pb, "%sfunction %s(...) { [native code] }%s",
		level ? "\"" : "", fn->name, level ? "\"" : "");
}

static void
ut_c_fn_free(struct json_object *v, void *ud)
{
	struct ut_op *op = ud;

	json_object_put(op->tag.proto);
	free(ud);
}

static bool
ut_register_function(struct ut_state *state, struct json_object *scope, const char *name, ut_c_fn *cfn)
{
	struct json_object *val = xjs_new_object();
	struct ut_function *fn;
	struct ut_op *op;

	op = xalloc(ALIGN(sizeof(*op)) + ALIGN(sizeof(*fn)) + ALIGN(strlen(name) + 1));
	op->val = val;
	op->type = T_CFUNC;

	fn = (void *)op + ALIGN(sizeof(*op));
	fn->source = state->function ? state->function->source : NULL;
	fn->name = strcpy((char *)fn + ALIGN(sizeof(*fn)), name);
	fn->cfn = cfn;

	op->tag.data = fn;

	json_object_set_serializer(val, ut_c_fn_to_string, op, ut_c_fn_free);

	return json_object_object_add(scope, name, op->val);
}

static struct json_object *
ut_print_common(struct ut_state *s, uint32_t off, struct json_object *args, FILE *fh)
{
	struct json_object *item;
	size_t arridx, arrlen;
	size_t reslen = 0;
	size_t len = 0;
	const char *p;

	for (arridx = 0, arrlen = json_object_array_length(args);
	     arridx < arrlen; arridx++) {
		item = json_object_array_get_idx(args, arridx);

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


static struct json_object *
ut_print(struct ut_state *s, uint32_t off, struct json_object *args)
{
	return ut_print_common(s, off, args, stdout);
}

static struct json_object *
ut_length(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *arg = json_object_array_get_idx(args, 0);
	size_t len;

	switch (json_object_get_type(arg)) {
	case json_type_object:
		len = 0;

		json_object_object_foreach(arg, k, v) {
			(void)k;
			(void)v;
			len++;
		}

		return xjs_new_int64(len);

	case json_type_array:
		return xjs_new_int64(json_object_array_length(arg));

	case json_type_string:
		return xjs_new_int64(json_object_get_string_len(arg));

	default:
		return NULL;
	}
}

static struct json_object *
ut_index(struct ut_state *s, uint32_t off, struct json_object *args, bool right)
{
	struct json_object *stack = json_object_array_get_idx(args, 0);
	struct json_object *needle = json_object_array_get_idx(args, 1);
	size_t arridx, len, ret = -1;
	const char *sstr, *nstr, *p;

	switch (json_object_get_type(stack)) {
	case json_type_array:
		for (arridx = 0, len = json_object_array_length(stack); arridx < len; arridx++) {
			if (ut_cmp(T_EQ, json_object_array_get_idx(stack, arridx), needle)) {
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

static struct json_object *
ut_lindex(struct ut_state *s, uint32_t off, struct json_object *args)
{
	return ut_index(s, off, args, false);
}

static struct json_object *
ut_rindex(struct ut_state *s, uint32_t off, struct json_object *args)
{
	return ut_index(s, off, args, true);
}

static struct json_object *
ut_push(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *arr = json_object_array_get_idx(args, 0);
	struct json_object *item = NULL;
	size_t arridx, arrlen;

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	for (arridx = 1, arrlen = json_object_array_length(args);
	     arridx < arrlen; arridx++) {
		item = json_object_array_get_idx(args, arridx);
		json_object_array_add(arr, json_object_get(item));
	}

	return json_object_get(item);
}

static struct json_object *
ut_pop(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *arr = json_object_array_get_idx(args, 0);
	struct json_object *item = NULL;
	size_t arrlen;

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	arrlen = json_object_array_length(arr);

	if (arrlen > 0) {
		item = json_object_array_get_idx(arr, arrlen - 1);
		json_object_array_del_idx(arr, arrlen - 1, 1);
#ifdef HAVE_ARRAY_SHRINK
		json_object_array_shrink(arr, 0);
#endif
	}

	return json_object_get(item);
}

static struct json_object *
ut_shift(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *arr = json_object_array_get_idx(args, 0);
	struct json_object *item = NULL;
	size_t arridx, arrlen;

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	item = json_object_get(json_object_array_get_idx(arr, 0));
	arrlen = json_object_array_length(arr);

	for (arridx = 0; arridx < arrlen - 1; arridx++)
		json_object_array_put_idx(arr, arridx,
			json_object_array_get_idx(arr, arridx + 1));

	json_object_array_del_idx(arr, arrlen - 1, 1);
#ifdef HAVE_ARRAY_SHRINK
	json_object_array_shrink(arr, 0);
#endif

	return item;
}

static struct json_object *
ut_unshift(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *arr = json_object_array_get_idx(args, 0);
	struct json_object *item = NULL;
	size_t arridx, arrlen, addlen;

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	arrlen = json_object_array_length(arr);
	addlen = json_object_array_length(args) - 1;

	for (arridx = arrlen; arridx > 0; arridx--)
		json_object_array_put_idx(arr, arridx + addlen - 1,
			json_object_get(json_object_array_get_idx(arr, arridx - 1)));

	for (arridx = 0; arridx < addlen; arridx++) {
		item = json_object_array_get_idx(args, arridx + 1);
		json_object_array_put_idx(arr, arridx, json_object_get(item));
	}

	return item;
}

static struct json_object *
ut_chr(struct ut_state *s, uint32_t off, struct json_object *args)
{
	size_t len = json_object_array_length(args);
	size_t idx;
	int64_t n;
	char *str;

	if (!len)
		return xjs_new_string_len("", 0);

	str = xalloc(len);

	for (idx = 0; idx < len; idx++) {
		n = ut_cast_int64(json_object_array_get_idx(args, idx));

		if (n < 0)
			n = 0;
		else if (n > 255)
			n = 255;

		str[idx] = (char)n;
	}

	return xjs_new_string_len(str, len);
}

static struct json_object *
ut_delete(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *obj = json_object_array_get_idx(args, 0);
	struct json_object *rv = NULL;
	size_t arridx, arrlen;
	const char *key;

	if (!json_object_is_type(obj, json_type_object))
		return NULL;

	for (arrlen = json_object_array_length(args), arridx = 1; arridx < arrlen; arridx++) {
		json_object_put(rv);

		key = json_object_get_string(json_object_array_get_idx(args, arridx));
		rv = json_object_get(json_object_object_get(obj, key ? key : "null"));

		json_object_object_del(obj, key ? key : "null");
	}

	return rv;
}

static struct json_object *
ut_die(struct ut_state *s, uint32_t off, struct json_object *args)
{
	const char *msg = json_object_get_string(json_object_array_get_idx(args, 0));
	struct ut_function *prev_fn;
	struct json_object *ex;

	prev_fn = s->function;
	s->function = s->callstack->function;

	ex = ut_new_exception(s, s->callstack->off, "%s", msg ? msg : "Died");

	s->function = prev_fn;

	return ex;
}

static struct json_object *
ut_exists(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *obj = json_object_array_get_idx(args, 0);
	const char *key = json_object_get_string(json_object_array_get_idx(args, 1));

	if (!json_object_is_type(obj, json_type_object))
		return false;

	return xjs_new_boolean(json_object_object_get_ex(obj, key ? key : "null", NULL));
}

__attribute__((noreturn)) static struct json_object *
ut_exit(struct ut_state *s, uint32_t off, struct json_object *args)
{
	int64_t n = ut_cast_int64(json_object_array_get_idx(args, 0));

	exit(n);
}

static struct json_object *
ut_getenv(struct ut_state *s, uint32_t off, struct json_object *args)
{
	const char *key = json_object_get_string(json_object_array_get_idx(args, 0));
	char *val = key ? getenv(key) : NULL;

	return val ? xjs_new_string(val) : NULL;
}

static struct json_object *
ut_filter(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *obj = json_object_array_get_idx(args, 0);
	struct json_object *func = json_object_array_get_idx(args, 1);
	struct json_object *rv, *arr, *cmpargs;
	size_t arridx, arrlen;

	if (!json_object_is_type(obj, json_type_array))
		return NULL;

	arr = xjs_new_array();
	cmpargs = xjs_new_array();

	json_object_array_put_idx(cmpargs, 2, json_object_get(obj));

	for (arrlen = json_object_array_length(obj), arridx = 0; arridx < arrlen; arridx++) {
		json_object_array_put_idx(cmpargs, 0, json_object_get(json_object_array_get_idx(obj, arridx)));
		json_object_array_put_idx(cmpargs, 1, xjs_new_int64(arridx));

		rv = ut_invoke(s, off, NULL, func, cmpargs);

		if (ut_is_type(rv, T_EXCEPTION)) {
			json_object_put(cmpargs);
			json_object_put(arr);

			return rv;
		}

		if (ut_val_is_truish(rv))
			json_object_array_add(arr, json_object_get(json_object_array_get_idx(obj, arridx)));

		json_object_put(rv);
	}

	json_object_put(cmpargs);

	return arr;
}

static struct json_object *
ut_hex(struct ut_state *s, uint32_t off, struct json_object *args)
{
	const char *val = json_object_get_string(json_object_array_get_idx(args, 0));
	int64_t n;
	char *e;

	if (!val || !isxdigit(*val))
		return ut_new_double(NAN);

	n = strtoll(val, &e, 16);

	if (e == val || *e)
		return ut_new_double(NAN);

	return xjs_new_int64(n);
}

static struct json_object *
ut_int(struct ut_state *s, uint32_t off, struct json_object *args)
{
	int64_t n = ut_cast_int64(json_object_array_get_idx(args, 0));

	if (errno == EINVAL || errno == EOVERFLOW)
		return ut_new_double(NAN);

	return xjs_new_int64(n);
}

static struct json_object *
ut_join(struct ut_state *s, uint32_t off, struct json_object *args)
{
	const char *sep = json_object_get_string(json_object_array_get_idx(args, 0));
	struct json_object *arr = json_object_array_get_idx(args, 1);
	struct json_object *rv = NULL;
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

static struct json_object *
ut_keys(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *obj = json_object_array_get_idx(args, 0);
	struct json_object *arr = NULL;

	if (!json_object_is_type(obj, json_type_object))
		return NULL;

	arr = xjs_new_array();

	json_object_object_foreach(obj, key, val)
		json_object_array_add(arr, xjs_new_string(key));

	return arr;
}

static struct json_object *
ut_lc(struct ut_state *s, uint32_t off, struct json_object *args)
{
	const char *str = json_object_get_string(json_object_array_get_idx(args, 0));
	size_t len = str ? strlen(str) : 0;
	struct json_object *rv = NULL;
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

static struct json_object *
ut_map(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *obj = json_object_array_get_idx(args, 0);
	struct json_object *func = json_object_array_get_idx(args, 1);
	struct json_object *arr, *cmpargs, *rv;
	size_t arridx, arrlen;

	if (!json_object_is_type(obj, json_type_array))
		return NULL;

	arr = xjs_new_array();
	cmpargs = xjs_new_array();

	json_object_array_put_idx(cmpargs, 2, json_object_get(obj));

	for (arrlen = json_object_array_length(obj), arridx = 0; arridx < arrlen; arridx++) {
		json_object_array_put_idx(cmpargs, 0, json_object_get(json_object_array_get_idx(obj, arridx)));
		json_object_array_put_idx(cmpargs, 1, xjs_new_int64(arridx));

		rv = ut_invoke(s, off, NULL, func, cmpargs);

		if (ut_is_type(rv, T_EXCEPTION)) {
			json_object_put(cmpargs);
			json_object_put(arr);

			return rv;
		}

		json_object_array_add(arr, rv);
	}

	json_object_put(cmpargs);

	return arr;
}

static struct json_object *
ut_ord(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *obj = json_object_array_get_idx(args, 0);
	struct json_object *rv, *pos;
	size_t i, len, nargs;
	const char *str;
	int64_t n;

	if (!json_object_is_type(obj, json_type_string))
		return NULL;

	str = json_object_get_string(obj);
	len = json_object_get_string_len(obj);

	nargs = json_object_array_length(args);

	if (nargs == 1)
		return str[0] ? xjs_new_int64((int64_t)str[0]) : NULL;

	rv = xjs_new_array();

	for (i = 1; i < nargs; i++) {
		pos = json_object_array_get_idx(args, i);

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

static struct json_object *
ut_type(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *v = json_object_array_get_idx(args, 0);
	struct ut_op *tag = json_object_get_userdata(v);

	switch (tag ? tag->type : 0) {
	case T_FUNC:
		return xjs_new_string("function");

	case T_RESSOURCE:
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

static struct json_object *
ut_reverse(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *obj = json_object_array_get_idx(args, 0);
	struct json_object *rv = NULL;
	size_t len, arridx;
	const char *str;
	char *dup, *p;

	if (json_object_is_type(obj, json_type_array)) {
		rv = xjs_new_array();

		for (arridx = json_object_array_length(obj); arridx > 0; arridx--)
			json_object_array_add(rv, json_object_get(json_object_array_get_idx(obj, arridx - 1)));
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
	struct ut_state *s;
	uint32_t off;
	struct json_object *fn;
	struct json_object *args;
	struct json_object *ex;
} sort_ctx;

static int
sort_fn(const void *k1, const void *k2)
{
	struct json_object * const *v1 = k1;
	struct json_object * const *v2 = k2;
	struct json_object *rv;
	int ret;

	if (!sort_ctx.fn)
		return !ut_cmp(T_LT, *v1, *v2);

	if (sort_ctx.ex)
		return 0;

	json_object_array_put_idx(sort_ctx.args, 0, json_object_get(*v1));
	json_object_array_put_idx(sort_ctx.args, 1, json_object_get(*v2));

	rv = ut_invoke(sort_ctx.s, sort_ctx.off, NULL, sort_ctx.fn, sort_ctx.args);

	if (ut_is_type(rv, T_EXCEPTION)) {
		sort_ctx.ex = rv;

		return 0;
	}

	ret = !ut_val_is_truish(rv);

	json_object_put(rv);

	return ret;
}

static struct json_object *
ut_sort(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *arr = json_object_array_get_idx(args, 0);
	struct json_object *fn = json_object_array_get_idx(args, 1);

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	if (fn) {
		sort_ctx.s = s;
		sort_ctx.off = off;
		sort_ctx.fn = fn;
		sort_ctx.args = xjs_new_array();
	}

	json_object_array_sort(arr, sort_fn);
	json_object_put(sort_ctx.args);

	return sort_ctx.ex ? sort_ctx.ex : json_object_get(arr);
}

static struct json_object *
ut_splice(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *arr = json_object_array_get_idx(args, 0);
	int64_t ofs = ut_cast_int64(json_object_array_get_idx(args, 1));
	int64_t remlen = ut_cast_int64(json_object_array_get_idx(args, 2));
	size_t arrlen, addlen, idx;

	if (!json_object_is_type(arr, json_type_array))
		return NULL;

	arrlen = json_object_array_length(arr);
	addlen = json_object_array_length(args);

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
				json_object_get(json_object_array_get_idx(arr, idx - 1)));
	}

	for (idx = 0; idx < addlen; idx++)
		json_object_array_put_idx(arr, ofs + idx,
			json_object_get(json_object_array_get_idx(args, 3 + idx)));

	return json_object_get(arr);
}

static struct json_object *
ut_split(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *str = json_object_array_get_idx(args, 0);
	struct json_object *sep = json_object_array_get_idx(args, 1);
	struct json_object *arr = NULL;
	const char *p, *sepstr, *splitstr;
	int eflags = 0, res;
	regmatch_t pmatch;
	struct ut_op *tag;
	size_t seplen;

	if (!sep || !json_object_is_type(str, json_type_string))
		return NULL;

	arr = xjs_new_array();
	splitstr = json_object_get_string(str);

	if (ut_is_type(sep, T_REGEXP)) {
		tag = json_object_get_userdata(sep);

		while (true) {
			res = regexec((regex_t *)tag->tag.data, splitstr, 1, &pmatch, eflags);

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
		json_object_put(arr);

		return NULL;
	}

	return arr;
}

static struct json_object *
ut_substr(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *str = json_object_array_get_idx(args, 0);
	int64_t ofs = ut_cast_int64(json_object_array_get_idx(args, 1));
	int64_t sublen = ut_cast_int64(json_object_array_get_idx(args, 2));
	const char *p;
	size_t len;

	if (!json_object_is_type(str, json_type_string))
		return NULL;

	p = json_object_get_string(str);
	len = json_object_get_string_len(str);

	switch (json_object_array_length(args)) {
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

static struct json_object *
ut_time(struct ut_state *s, uint32_t off, struct json_object *args)
{
	time_t t = time(NULL);

	return xjs_new_int64((int64_t)t);
}

static struct json_object *
ut_uc(struct ut_state *s, uint32_t off, struct json_object *args)
{
	const char *str = json_object_get_string(json_object_array_get_idx(args, 0));
	size_t len = str ? strlen(str) : 0;
	struct json_object *rv = NULL;
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

static struct json_object *
ut_uchr(struct ut_state *s, uint32_t off, struct json_object *args)
{
	size_t len = json_object_array_length(args);
	size_t idx, ulen;
	char *p, *str;
	int64_t n;
	int rem;

	for (idx = 0, ulen = 0; idx < len; idx++) {
		n = ut_cast_int64(json_object_array_get_idx(args, idx));

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

	for (idx = 0, p = str, rem = ulen; idx < len; idx++) {
		n = ut_cast_int64(json_object_array_get_idx(args, idx));

		if (errno == EINVAL || errno == EOVERFLOW || n < 0 || n > 0x10FFFF)
			n = 0xFFFD;

		if (!utf8enc(&p, &rem, n))
			break;
	}

	return xjs_new_string_len(str, ulen);
}

static struct json_object *
ut_values(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *obj = json_object_array_get_idx(args, 0);
	struct json_object *arr;

	if (!json_object_is_type(obj, json_type_object))
		return NULL;

	arr = xjs_new_array();

	json_object_object_foreach(obj, key, val) {
		(void)key;
		json_object_array_add(arr, json_object_get(val));
	}

	return arr;
}

static struct json_object *
ut_trim_common(struct ut_state *s, uint32_t off, struct json_object *args, bool start, bool end)
{
	struct json_object *str = json_object_array_get_idx(args, 0);
	struct json_object *chr = json_object_array_get_idx(args, 1);
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

static struct json_object *
ut_trim(struct ut_state *s, uint32_t off, struct json_object *args)
{
	return ut_trim_common(s, off, args, true, true);
}

static struct json_object *
ut_ltrim(struct ut_state *s, uint32_t off, struct json_object *args)
{
	return ut_trim_common(s, off, args, true, false);
}

static struct json_object *
ut_rtrim(struct ut_state *s, uint32_t off, struct json_object *args)
{
	return ut_trim_common(s, off, args, false, true);
}

static size_t
ut_printf_common(struct ut_state *s, uint32_t off, struct json_object *args, char **res)
{
	struct json_object *fmt = json_object_array_get_idx(args, 0);
	char *fp, sfmt[sizeof("%0- 123456789.123456789%")];
	union { const char *s; int64_t n; double d; } arg;
	size_t len = 0, arglen, argidx;
	const char *fstr, *last, *p;
	enum json_type t;

	*res = NULL;

	if (json_object_is_type(fmt, json_type_string))
		fstr = json_object_get_string(fmt);
	else
		fstr = "";

	arglen = json_object_array_length(args);
	argidx = 1;

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

				if (argidx < arglen)
					arg.n = ut_cast_int64(json_object_array_get_idx(args, argidx++));
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

				if (argidx < arglen)
					arg.d = ut_cast_double(json_object_array_get_idx(args, argidx++));
				else
					arg.d = 0;

				break;

			case 'c':
				t = json_type_int;

				if (argidx < arglen)
					arg.n = ut_cast_int64(json_object_array_get_idx(args, argidx++)) & 0xff;
				else
					arg.n = 0;

				break;

			case 's':
				t = json_type_string;

				if (argidx < arglen)
					arg.s = json_object_get_string(json_object_array_get_idx(args, argidx++));
				else
					arg.s = NULL;

				arg.s = arg.s ? arg.s : "(null)";

				break;

			case 'J':
				t = json_type_string;

				if (argidx < arglen)
					arg.s = json_object_to_json_string_ext(
						json_object_array_get_idx(args, argidx++),
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

static struct json_object *
ut_sprintf(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *rv;
	char *str = NULL;
	size_t len;

	len = ut_printf_common(s, off, args, &str);
	rv = xjs_new_string_len(str, len);

	free(str);

	return rv;
}

static struct json_object *
ut_printf(struct ut_state *s, uint32_t off, struct json_object *args)
{
	char *str = NULL;
	size_t len;

	len = ut_printf_common(s, off, args, &str);
	len = fwrite(str, 1, len, stdout);

	free(str);

	return xjs_new_int64(len);
}

static struct json_object *
ut_require_so(struct ut_state *s, uint32_t off, const char *path)
{
	void (*init)(const struct ut_ops *, struct ut_state *, struct json_object *);
	struct ut_op *op = ut_get_op(s, off);
	struct ut_function fn = {}, *prev_fn;
	struct ut_source *src, *prev_src;
	struct json_object *scope;
	struct stat st;
	void *dlh;

	if (stat(path, &st))
		return NULL;

	dlerror();
	dlh = dlopen(path, RTLD_LAZY|RTLD_LOCAL);

	if (!dlh)
		return ut_new_exception(s, op->off, "Unable to dlopen file %s: %s", path, dlerror());

	init = dlsym(dlh, "ut_module_init");

	if (!init)
		return ut_new_exception(s, op->off, "Module %s provides no 'ut_module_init' function", path);

	src = xalloc(sizeof(*src));
	src->filename = xstrdup(path);
	src->next = s->sources;

	fn.name = "require";
	fn.source = src;

	prev_fn = s->function;
	s->function = &fn;

	prev_src = s->source;
	s->source = s->sources = src;

	scope = xjs_new_object();

	init(&ut, s, scope);

	s->source = prev_src;
	s->function = prev_fn;

	return scope;
}

struct json_object *
ut_execute_source(struct ut_state *s, struct ut_source *src, struct ut_scope *scope)
{
	struct json_object *entry, *rv;

	rv = ut_parse(s, src->fp);

	if (!ut_is_type(rv, T_EXCEPTION)) {
		entry = ut_new_func(s, ut_get_op(s, s->main), scope ? scope : s->scope);

		json_object_put(rv);
		rv = ut_invoke(s, s->main, NULL, entry, NULL);

		json_object_put(entry);
	}

	return rv;
}

static struct json_object *
ut_require_utpl(struct ut_state *s, uint32_t off, const char *path, struct ut_scope *scope)
{
	struct ut_op *op = ut_get_op(s, off);
	struct ut_function fn = {}, *prev_fn;
	struct ut_source *src, *prev_src;
	struct json_object *rv;
	struct stat st;
	FILE *fp;

	if (stat(path, &st))
		return NULL;

	fp = fopen(path, "rb");

	if (!fp)
		return ut_new_exception(s, op->off, "Unable to open file %s: %s", path, strerror(errno));

	src = xalloc(sizeof(*src));
	src->fp = fp;
	src->filename = path ? xstrdup(path) : NULL;
	src->next = s->sources;

	prev_src = s->source;
	s->source = s->sources = src;

	fn.name = "require";
	fn.source = src;

	prev_fn = s->function;
	s->function = &fn;

	rv = ut_execute_source(s, src, scope);

	s->function = prev_fn;
	s->source = prev_src;

	return rv;
}

static struct json_object *
ut_require_path(struct ut_state *s, uint32_t off, const char *path_template, const char *name)
{
	struct json_object *rv = NULL;
	const char *p, *q, *last;
	char *path = NULL;
	size_t plen = 0;

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
		rv = ut_require_so(s, off, path);
	else if (!strcmp(p, ".utpl"))
		rv = ut_require_utpl(s, off, path, NULL);

invalid:
	free(path);

	return rv;
}

static struct json_object *
ut_require(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *val = json_object_array_get_idx(args, 0);
	struct json_object *search, *se, *res;
	struct ut_op *op = ut_get_op(s, off);
	struct ut_scope *sc, *scparent;
	size_t arridx, arrlen;
	const char *name;

	if (!json_object_is_type(val, json_type_string))
		return NULL;

	/* find root scope */
	for (sc = s->scope; sc; ) {
		scparent = ut_parent_scope(sc);

		if (!scparent)
			break;

		sc = scparent;
	}

	name = json_object_get_string(val);
	search = sc ? json_object_object_get(sc->scope, "REQUIRE_SEARCH_PATH") : NULL;

	if (!json_object_is_type(search, json_type_array))
		return ut_new_exception(s, op ? op->off : 0,
		                        "Global require search path not set");

	for (arridx = 0, arrlen = json_object_array_length(search); arridx < arrlen; arridx++) {
		se = json_object_array_get_idx(search, arridx);

		if (!json_object_is_type(se, json_type_string))
			continue;

		res = ut_require_path(s, off, json_object_get_string(se), name);

		if (res)
			return res;
	}

	return ut_new_exception(s, op ? op->off : 0,
	                        "No module named '%s' could be found", name);
}

static struct json_object *
ut_iptoarr(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *ip = json_object_array_get_idx(args, 0);
	struct json_object *res;
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
check_byte(struct json_object *v)
{
	int n;

	if (!json_object_is_type(v, json_type_int))
		return -1;

	n = json_object_get_int(v);

	if (n < 0 || n > 255)
		return -1;

	return n;
}

static struct json_object *
ut_arrtoip(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *arr = json_object_array_get_idx(args, 0);
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

static struct json_object *
ut_match(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *subject = json_object_array_get_idx(args, 0);
	struct json_object *pattern = json_object_array_get_idx(args, 1);
	struct ut_op *tag = json_object_get_userdata(pattern);
	struct json_object *rv = NULL, *m;
	int eflags = 0, res, i;
	regmatch_t pmatch[10];
	const char *p;

	if (!ut_is_type(pattern, T_REGEXP) || !subject)
		return NULL;

	p = json_object_get_string(subject);

	while (true) {
		res = regexec((regex_t *)tag->tag.data, p, ARRAY_SIZE(pmatch), pmatch, eflags);

		if (res == REG_NOMATCH)
			break;

		m = xjs_new_array();

		for (i = 0; i < ARRAY_SIZE(pmatch) && pmatch[i].rm_so != -1; i++) {
			json_object_array_add(m,
				xjs_new_string_len(p + pmatch[i].rm_so,
				                   pmatch[i].rm_eo - pmatch[i].rm_so));
		}

		if (tag->is_reg_global) {
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

static struct json_object *
ut_replace_cb(struct ut_state *s, uint32_t off, struct json_object *func,
              const char *subject, regmatch_t *pmatch, size_t plen,
              char **sp, size_t *sl)
{
	struct json_object *cbargs = xjs_new_array();
	struct json_object *rv;
	size_t i;

	for (i = 0; i < plen && pmatch[i].rm_so != -1; i++) {
		json_object_array_add(cbargs,
			xjs_new_string_len(subject + pmatch[i].rm_so,
			                   pmatch[i].rm_eo - pmatch[i].rm_so));
	}

	rv = ut_invoke(s, off, NULL, func, cbargs);

	if (ut_is_type(rv, T_EXCEPTION)) {
		json_object_put(cbargs);

		return rv;
	}

	sprintf_append(sp, sl, "%s", rv ? json_object_get_string(rv) : "null");

	json_object_put(cbargs);
	json_object_put(rv);

	return NULL;
}

static void
ut_replace_str(struct ut_state *s, uint32_t off, struct json_object *str,
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

static struct json_object *
ut_replace(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *subject = json_object_array_get_idx(args, 0);
	struct json_object *pattern = json_object_array_get_idx(args, 1);
	struct json_object *replace = json_object_array_get_idx(args, 2);
	struct ut_op *tag = json_object_get_userdata(pattern);
	struct json_object *rv = NULL;
	const char *sb, *p, *l;
	regmatch_t pmatch[10];
	int eflags = 0, res;
	size_t sl = 0, pl;
	char *sp = NULL;

	if (!pattern || !subject || !replace)
		return NULL;

	if (ut_is_type(pattern, T_REGEXP)) {
		p = json_object_get_string(subject);

		while (true) {
			res = regexec((regex_t *)tag->tag.data, p, ARRAY_SIZE(pmatch), pmatch, eflags);

			if (res == REG_NOMATCH)
				break;

			snprintf_append(&sp, &sl, "%s", pmatch[0].rm_so, p);

			if (ut_is_type(replace, T_FUNC) || ut_is_type(replace, T_CFUNC)) {
				rv = ut_replace_cb(s, off, replace, p, pmatch, ARRAY_SIZE(pmatch), &sp, &sl);

				if (rv) {
					free(sp);

					return rv;
				}
			}
			else {
				ut_replace_str(s, off, replace, p, pmatch, ARRAY_SIZE(pmatch), &sp, &sl);
			}

			p += pmatch[0].rm_eo;

			if (tag->is_reg_global)
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

				if (ut_is_type(replace, T_FUNC) || ut_is_type(replace, T_CFUNC)) {
					rv = ut_replace_cb(s, off, replace, l, pmatch, 1, &sp, &sl);

					if (rv) {
						free(sp);

						return rv;
					}
				}
				else {
					ut_replace_str(s, off, replace, l, pmatch, 1, &sp, &sl);
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

static struct json_object *
ut_json(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *rv, *src = json_object_array_get_idx(args, 0);
	struct ut_op *op = ut_get_op(s, off);
	struct json_tokener *tok = NULL;
	enum json_tokener_error err;
	const char *str;
	size_t len;

	if (!json_object_is_type(src, json_type_string))
		return ut_new_exception(s, op->off, "Passed value is not a string");

	tok = xjs_new_tokener();
	str = json_object_get_string(src);
	len = json_object_get_string_len(src);

	rv = json_tokener_parse_ex(tok, str, len);
	err = json_tokener_get_error(tok);

	if (err == json_tokener_continue) {
		json_object_put(rv);
		rv = ut_new_exception(s, op->off, "Unexpected end of string in JSON data");
	}
	else if (err != json_tokener_success) {
		json_object_put(rv);
		rv = ut_new_exception(s, op->off, "Failed to parse JSON string: %s",
		                  json_tokener_error_desc(err));
	}
	else if (json_tokener_get_parse_end(tok) < len) {
		json_object_put(rv);
		rv = ut_new_exception(s, op->off, "Trailing garbage after JSON data");
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

static struct json_object *
ut_include(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *rv, *path = json_object_array_get_idx(args, 0);
	struct json_object *scope = json_object_array_get_idx(args, 1);
	struct ut_op *op = ut_get_op(s, off);
	struct ut_scope *sc;
	char *p;

	if (!json_object_is_type(path, json_type_string))
		return ut_new_exception(s, op->off, "Passed filename is not a string");

	if (scope && !json_object_is_type(scope, json_type_object))
		return ut_new_exception(s, op->off, "Passed scope value is not an object");

	p = include_path(s->callstack->function->source->filename, json_object_get_string(path));

	if (!p)
		return ut_new_exception(s, op->off, "Include file not found");

	if (scope) {
		sc = ut_new_scope(s, NULL);

		json_object_object_foreach(scope, key, val)
			json_object_object_add(sc->scope, key, json_object_get(val));
	}
	else {
		sc = s->scope;
	}

	rv = ut_require_utpl(s, off, p, sc);

	free(p);

	if (scope)
		json_object_put(sc->scope);

	if (ut_is_type(rv, T_EXCEPTION))
		return rv;

	json_object_put(rv);

	return NULL;
}

static struct json_object *
ut_warn(struct ut_state *s, uint32_t off, struct json_object *args)
{
	return ut_print_common(s, off, args, stderr);
}

static struct json_object *
ut_system(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *cmdline = json_object_array_get_idx(args, 0);
	struct json_object *timeout = json_object_array_get_idx(args, 1);
	struct ut_op *op = ut_get_op(s, off);
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
		return ut_new_exception(s, op->off, "Passed command is neither string nor array");
	}

	if (timeout && (!json_object_is_type(timeout, json_type_int) || json_object_get_int64(timeout) < 0))
		return ut_new_exception(s, op->off, "Invalid timeout specified");

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
		execv(arglist[0], (char * const *)arglist);
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
	sigprocmask(SIG_SETMASK, &sigomask, NULL);
	free(arglist);

	return ut_new_exception(s, op->off, "%s(): %s", fn, strerror(errno));
}

const struct ut_ops ut = {
	.register_function = ut_register_function,
	.register_type = ut_register_extended_type,
	.set_type = ut_set_extended_type,
	.get_type = ut_get_extended_type,
	.new_object = ut_new_object,
	.new_double = ut_new_double,
	.invoke = ut_invoke,
	.cast_number = ut_cast_number,
};

static const struct { const char *name; ut_c_fn *func; } functions[] = {
	{ "chr",		ut_chr },
	{ "delete",		ut_delete },
	{ "die",		ut_die },
	{ "exists",		ut_exists },
	{ "exit",		ut_exit },
	{ "filter",		ut_filter },
	{ "getenv",		ut_getenv },
	{ "hex",		ut_hex },
	{ "index",		ut_lindex },
	{ "int",		ut_int },
	{ "join",		ut_join },
	{ "keys",		ut_keys },
	{ "lc",			ut_lc },
	{ "length",		ut_length },
	{ "ltrim",		ut_ltrim },
	{ "map",		ut_map },
	{ "ord",		ut_ord },
	{ "pop",		ut_pop },
	{ "print",		ut_print },
	{ "push",		ut_push },
	{ "reverse",	ut_reverse },
	{ "rindex",		ut_rindex },
	{ "rtrim",		ut_rtrim },
	{ "shift",		ut_shift },
	{ "sort",		ut_sort },
	{ "splice",		ut_splice },
	{ "split",		ut_split },
	{ "substr",		ut_substr },
	{ "time",		ut_time },
	{ "trim",		ut_trim },
	{ "type",		ut_type },
	{ "uchr",		ut_uchr },
	{ "uc",			ut_uc },
	{ "unshift",	ut_unshift },
	{ "values",		ut_values },
	{ "sprintf",	ut_sprintf },
	{ "printf",		ut_printf },
	{ "require",	ut_require },
	{ "iptoarr",	ut_iptoarr },
	{ "arrtoip",	ut_arrtoip },
	{ "match",		ut_match },
	{ "replace",	ut_replace },
	{ "json",		ut_json },
	{ "include",	ut_include },
	{ "warn",		ut_warn },
	{ "system",		ut_system },
};


void
ut_lib_init(struct ut_state *state, struct json_object *scope)
{
	int i;

	for (i = 0; i < sizeof(functions) / sizeof(functions[0]); i++)
		ut_register_function(state, scope, functions[i].name, functions[i].func);
}
