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
#include "lib.h"
#include "lexer.h"
#include "parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>
#include <regex.h>

static size_t ut_ext_types_count = 0;
static struct ut_extended_type *ut_ext_types = NULL;

struct ut_op *
ut_get_op(struct ut_state *s, uint32_t off)
{
	if (off == 0 || off > s->poolsize)
		return NULL;

	return &s->pool[off - 1];
}

struct ut_op *
ut_get_child(struct ut_state *s, uint32_t off, int n)
{
	struct ut_op *op = ut_get_op(s, off);

	if (!op || n >= ARRAY_SIZE(op->tree.operand) || !op->tree.operand[n])
		return NULL;

	return ut_get_op(s, op->tree.operand[n]);
}

uint32_t
ut_new_op(struct ut_state *s, int type, struct json_object *val, ...)
{
	struct ut_op *newop;
	uint32_t child;
	int n_op = 0;
	va_list ap;

	if ((s->poolsize + 1) == UINT32_MAX) {
		fprintf(stderr, "Program too large\n");
		exit(127);
	}

	s->pool = xrealloc(s->pool, (s->poolsize + 1) * sizeof(*newop));

	newop = &s->pool[s->poolsize];
	memset(newop, 0, sizeof(*newop));

	newop->is_first = !s->poolsize;
	newop->is_op = true;
	newop->type = type;
	newop->val = val;

	va_start(ap, val);

	while (n_op < ARRAY_SIZE(newop->tree.operand) && (child = va_arg(ap, uint32_t)) != UINT32_MAX)
		newop->tree.operand[n_op++] = child;

	va_end(ap);

	s->poolsize++;

	return s->poolsize;
}

uint32_t
ut_wrap_op(struct ut_state *s, uint32_t parent, ...)
{
	struct ut_op *op = ut_get_op(s, parent);
	uint32_t child;
	int n_op = 0;
	va_list ap;

	va_start(ap, parent);

	while (n_op < ARRAY_SIZE(op->tree.operand) && (child = va_arg(ap, uint32_t)) != UINT32_MAX)
		op->tree.operand[n_op++] = child;

	va_end(ap);

	return parent;
}

uint32_t
ut_append_op(struct ut_state *s, uint32_t a, uint32_t b)
{
	struct ut_op *tail = ut_get_op(s, a);

	while (tail && tail->tree.next)
		tail = ut_get_op(s, tail->tree.next);

	tail->tree.next = b;

	return a;
}

static int
double_rounded_to_string(struct json_object *v, struct printbuf *pb, int level, int flags)
{
	bool strict = (level > 0) || (flags & JSON_C_TO_STRING_STRICT);
	double d = json_object_get_double(v);

	if (isnan(d))
		return sprintbuf(pb, strict ? "\"NaN\"" : "NaN");

	if (d == INFINITY)
		return sprintbuf(pb, strict ? "1e309" : "Infinity");

	if (d == -INFINITY)
		return sprintbuf(pb, strict ? "-1e309" : "-Infinity");

	return sprintbuf(pb, "%g", d);
}

struct json_object *
ut_new_double(double v)
{
	struct json_object *d = json_object_new_double(v);

	if (!d) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	json_object_set_serializer(d, double_rounded_to_string, NULL, NULL);

	return d;
}

static int
null_obj_to_string(struct json_object *v, struct printbuf *pb, int level, int flags)
{
	return sprintbuf(pb, "null");
}

struct json_object *
ut_new_null(void)
{
	struct json_object *d = json_object_new_boolean(false);

	if (!d) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	json_object_set_serializer(d, null_obj_to_string, NULL, NULL);

	return d;
}

static void
obj_free(struct json_object *v, void *ud)
{
	struct ut_op *op = json_object_get_userdata(v);

	json_object_put(op->tag.proto);
	free(ud);
}

struct json_object *
ut_new_object(struct json_object *proto) {
	struct json_object *val = xjs_new_object();
	struct ut_op *op = xalloc(sizeof(*op));

	op->val = val;
	op->type = T_LBRACE;
	op->tag.proto = json_object_get(proto);

	json_object_set_serializer(val, NULL, op, obj_free);

	return op->val;
}

static void
re_free(struct json_object *v, void *ud)
{
	struct ut_op *op = ud;

	regfree((regex_t *)op->tag.data);
	free(op);
}

static int
re_to_string(struct json_object *v, struct printbuf *pb, int level, int flags)
{
	bool strict = (level > 0) || (flags & JSON_C_TO_STRING_STRICT);
	struct ut_op *op = json_object_get_userdata(v);
	struct json_object *s;
	const char *p;
	size_t len;

	sprintbuf(pb, "%s/", strict ? "\"" : "");

	s = xjs_new_string((char *)op + sizeof(*op) + sizeof(regex_t));

	if (strict)
		for (p = json_object_to_json_string(s) + 1, len = strlen(p) - 1; len > 0; len--, p++)
			sprintbuf(pb, "%c", *p);
	else
		sprintbuf(pb, "%s", json_object_get_string(s));

	json_object_put(s);

	return sprintbuf(pb, "/%s%s%s%s",
		             op->is_reg_global  ? "g" : "",
		             op->is_reg_icase   ? "i" : "",
		             op->is_reg_newline ? "s" : "",
		             strict ? "\"" : "");
}

struct json_object *
ut_new_regexp(const char *source, bool icase, bool newline, bool global, char **err) {
	int cflags = REG_EXTENDED, res;
	struct ut_op *op;
	regex_t *re;
	size_t len;

	op = xalloc(sizeof(*op) + sizeof(*re) + strlen(source) + 1);
	re = (regex_t *)((char *)op + sizeof(*op));
	strcpy((char *)op + sizeof(*op) + sizeof(*re), source);

	if (icase)
		cflags |= REG_ICASE;

	if (newline)
		cflags |= REG_NEWLINE;

	op->type = T_REGEXP;
	op->tag.data = re;
	op->is_reg_icase = icase;
	op->is_reg_global = global;
	op->is_reg_newline = newline;

	res = regcomp(re, source, cflags);

	if (res != 0) {
		len = regerror(res, re, NULL, 0);
		*err = xalloc(len);

		regerror(res, re, *err, len);
		free(op);

		return NULL;
	}

	op->val = xjs_new_object();

	if (!op->val) {
		free(op);

		return NULL;
	}

	json_object_set_serializer(op->val, re_to_string, op, re_free);

	return op->val;
}

static void
func_free(struct json_object *v, void *ud)
{
	struct ut_op *op = ud;
	struct ut_function *fn = op->tag.data;

	json_object_put(fn->args);
	ut_release_scope(fn->parent_scope);

	free(op);
}

static int
func_to_string(struct json_object *v, struct printbuf *pb, int level, int flags)
{
	bool strict = (level > 0) || (flags & JSON_C_TO_STRING_STRICT);
	struct ut_op *op = json_object_get_userdata(v);
	struct ut_function *fn = op->tag.data;
	size_t i;

	sprintbuf(pb, "%sfunction%s%s(",
	          strict ? "\"" : "",
	          fn->name ? " " : "",
	          fn->name ? fn->name : "");

	if (fn->args) {
		for (i = 0; i < json_object_array_length(fn->args); i++) {
			sprintbuf(pb, "%s%s",
			          i ? ", " : "",
			          json_object_get_string(json_object_array_get_idx(fn->args, i)));
		}
	}

	return sprintbuf(pb, ") { ... }%s", strict ? "\"" : "");
}

#define ALIGN(x) (((x) + sizeof(size_t) - 1) & -sizeof(size_t))

struct json_object *
ut_new_func(struct ut_state *s, struct ut_op *decl, struct ut_scope *scope)
{
	struct json_object *val = xjs_new_object();
	struct ut_op *op, *name, *args, *arg;
	struct ut_function *fn;
	size_t sz;

	sz = ALIGN(sizeof(*op)) + ALIGN(sizeof(*fn));

	name = ut_get_op(s, decl->tree.operand[0]);
	args = ut_get_op(s, decl->tree.operand[1]);

	if (name)
		sz += ALIGN(json_object_get_string_len(name->val) + 1);

	op = xalloc(sz);

	fn = (void *)op + ALIGN(sizeof(*op));
	fn->entry = decl->tree.operand[2];

	if (name)
		fn->name = strcpy((char *)fn + ALIGN(sizeof(*fn)), json_object_get_string(name->val));

	if (args) {
		fn->args = xjs_new_array();

		for (arg = args; arg; arg = ut_get_op(s, arg->tree.next))
			json_object_array_add(fn->args, json_object_get(arg->val));
	}

	fn->source = s->source;
	fn->parent_scope = ut_acquire_scope(scope);

	op->val = val;
	op->type = T_FUNC;
	op->tag.data = fn;

	json_object_set_serializer(val, func_to_string, op, func_free);

	return op->val;
}

static void
exception_free(struct json_object *v, void *ud)
{
	free(ud);
}

static int
exception_to_string(struct json_object *v, struct printbuf *pb, int level, int flags)
{
	return sprintbuf(pb, "%s", json_object_get_string(json_object_object_get(v, "message")));
}

static void
add_stacktrace(struct json_object *a, struct ut_source *source, const char *funcname, size_t off) {
	struct json_object *o = xjs_new_object();
	size_t line = 1, rlen = 0, len;
	bool truncated = false;
	char buf[256];

	if (source->filename)
		json_object_object_add(o, "filename", xjs_new_string(source->filename));

	if (funcname)
		json_object_object_add(o, "function", xjs_new_string(funcname));

	fseek(source->fp, 0, SEEK_SET);

	while (fgets(buf, sizeof(buf), source->fp)) {
		len = strlen(buf);
		rlen += len;

		if (rlen > off) {
			json_object_object_add(o, "line", xjs_new_int64(line));
			json_object_object_add(o, "byte", xjs_new_int64(len - (rlen - off) + (truncated ? sizeof(buf) : 0) + 1));
			break;
		}

		truncated = (len > 0 && buf[len-1] != '\n');
		line += !truncated;
	}

	json_object_array_add(a, o);
}

__attribute__((format(printf, 3, 4))) struct json_object *
ut_new_exception(struct ut_state *s, uint32_t off, const char *fmt, ...)
{
	struct ut_callstack *callstack;
	struct json_object *a;
	struct ut_op *op;
	va_list ap;
	char *p;
	int len;

	op = xalloc(sizeof(*op));
	op->type = T_EXCEPTION;
	op->val = xjs_new_object();
	op->off = off;
	op->tag.data = s->source;

	a = xjs_new_array();

	add_stacktrace(a,
	               s->function ? s->function->source : s->source,
	               s->function ? s->function->name : NULL,
	               off);

	for (callstack = s->callstack ? s->callstack->next : NULL; callstack; callstack = callstack->next)
		if (callstack->off)
			add_stacktrace(a, callstack->source, callstack->funcname, callstack->off);

	json_object_object_add(op->val, "stacktrace", a);

	va_start(ap, fmt);
	len = xvasprintf(&p, fmt, ap);
	va_end(ap);

	json_object_object_add(op->val, "message", xjs_new_string_len(p, len));
	free(p);

	if (s->exception)
		json_object_put(s->exception);

	s->exception = op->val;

	json_object_set_serializer(op->val, exception_to_string, op, exception_free);

	return json_object_get(op->val);
}

static void
scope_free(struct json_object *v, void *ud)
{
	struct ut_scope *sc = ud;

	if (sc->parent) {
		ut_release_scope(json_object_get_userdata(sc->parent));
		sc->parent = NULL;
	}

	sc->scope = NULL;
}

void
ut_release_scope(struct ut_scope *sc)
{
	if (sc->refs == 0)
		abort();

	sc->refs--;

	if (sc->refs == 0)
		json_object_put(sc->scope);
}

struct ut_scope *
ut_acquire_scope(struct ut_scope *sc)
{
	sc->refs++;

	return sc;
}

struct ut_scope *
ut_new_scope(struct ut_state *s, struct ut_scope *parent)
{
	struct ut_scope *sc;

	sc = xalloc(sizeof(*sc));
	sc->scope = xjs_new_object();

	if (parent)
		sc->parent = ut_acquire_scope(parent)->scope;

	json_object_set_userdata(sc->scope, sc, scope_free);

	sc->next = s->scopelist;
	s->scopelist = sc;

	return ut_acquire_scope(sc);
}

struct ut_scope *
ut_parent_scope(struct ut_scope *scope)
{
	return json_object_get_userdata(scope->parent);
}

static void
ut_reset(struct ut_state *s)
{
	json_object_put(s->exception);
	s->exception = NULL;

	free(s->lex.lookbehind);
	free(s->lex.buf);
	memset(&s->lex, 0, sizeof(s->lex));
}

void
ut_free(struct ut_state *s)
{
	struct ut_source *src, *src_next;
	struct ut_scope *sc, *sc_next;
	size_t n;

	if (s) {
		json_object_put(s->ctx);

		for (n = 0; n < s->poolsize; n++)
			json_object_put(s->pool[n].val);

		free(s->pool);

		s->pool = NULL;
		s->poolsize = 0;

		ut_reset(s);
	}

	while (ut_ext_types_count > 0)
		json_object_put(ut_ext_types[--ut_ext_types_count].proto);

	json_object_put(s->rval);

	for (sc = s->scopelist; sc; sc = sc->next) {
		json_object_put(sc->scope);
		sc->scope = NULL;
	}

	for (sc = s->scopelist; sc; sc = sc_next) {
		sc_next = sc->next;
		free(sc);
	}

	for (src = s->sources; src; src = src_next) {
		src_next = src->next;
		fclose(src->fp);
		free(src->filename);
		free(src);
	}

	free(ut_ext_types);
	free(s);
}

struct json_object *
ut_parse(struct ut_state *s, FILE *fp)
{
	struct ut_op *op;
	void *pParser;
	uint32_t off;

	ut_reset(s);

	pParser = ParseAlloc(xalloc);

	while (s->lex.state != UT_LEX_EOF) {
		off = ut_get_token(s, fp);
		op = ut_get_op(s, off);

		if (s->exception)
			goto out;

		if (op)
			Parse(pParser, op->type, off, s);

		if (s->exception)
			goto out;
	}

	Parse(pParser, 0, 0, s);

out:
	ParseFree(pParser, free);

	return s->exception;
}

bool
ut_register_extended_type(const char *name, struct json_object *proto, void (*freefn)(void *))
{
	ut_ext_types = xrealloc(ut_ext_types, (ut_ext_types_count + 1) * sizeof(*ut_ext_types));
	ut_ext_types[ut_ext_types_count].name = name;
	ut_ext_types[ut_ext_types_count].free = freefn;
	ut_ext_types[ut_ext_types_count].proto = proto;
	ut_ext_types_count++;

	return true;
}

static int
ut_extended_type_to_string(struct json_object *v, struct printbuf *pb, int level, int flags)
{
	bool strict = (level > 0) || (flags & JSON_C_TO_STRING_STRICT);
	struct ut_op *op = json_object_get_userdata(v);
	struct ut_extended_type *et;

	if (!op)
		return 0;

	et = &ut_ext_types[op->tag.type - 1];

	return sprintbuf(pb, "%s<%s %p>%s",
	                 strict ? "\"" : "",
	                 et->name, op->tag.data,
	                 strict ? "\"" : "");
}

static void
ut_extended_type_free(struct json_object *v, void *ud)
{
	struct ut_op *op = json_object_get_userdata(v);
	struct ut_extended_type *et;

	if (!op)
		return;

	et = &ut_ext_types[op->tag.type - 1];

	if (et->free && op->tag.data)
		et->free(op->tag.data);

	json_object_put(op->tag.proto);
	free(ud);
}

struct json_object *
ut_set_extended_type(struct json_object *v, const char *name, void *data)
{
	struct ut_extended_type *et = NULL;
	struct ut_op *op;
	size_t n;

	for (n = 0; n < ut_ext_types_count; n++) {
		if (!strcmp(name, ut_ext_types[n].name)) {
			et = &ut_ext_types[n];
			break;
		}
	}

	if (!et)
		return NULL;

	op = xalloc(sizeof(*op));
	op->val = v;
	op->type = T_RESSOURCE;
	op->tag.proto = json_object_get(et->proto);
	op->tag.type = n + 1;
	op->tag.data = data;

	json_object_set_serializer(op->val, ut_extended_type_to_string, op, ut_extended_type_free);

	return op->val;
}

void **
ut_get_extended_type(struct json_object *v, const char *name)
{
	struct ut_op *op = json_object_get_userdata(v);
	size_t n = op ? op->tag.type : 0;
	struct ut_extended_type *et;

	if (!op || op->type != T_RESSOURCE || n == 0 || n > ut_ext_types_count)
		return NULL;

	et = &ut_ext_types[n - 1];

	if (name && strcmp(et->name, name))
		return NULL;

	return &op->tag.data;
}
