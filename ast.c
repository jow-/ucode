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

static size_t uc_ext_types_count = 0;
static struct uc_extended_type *uc_ext_types = NULL;

uint32_t
uc_new_op(struct uc_state *s, int type, struct json_object *val, ...)
{
	struct uc_op *newop;
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

	while (n_op < OPn_NUM && (child = va_arg(ap, uint32_t)) != UINT32_MAX)
		newop->tree.operand[n_op++] = child;

	va_end(ap);

	return s->poolsize++;
}

uint32_t
uc_wrap_op(struct uc_state *state, uint32_t parent, ...)
{
	uint32_t child;
	int n_op = 0;
	va_list ap;

	va_start(ap, parent);

	while (n_op < OPn_NUM && (child = va_arg(ap, uint32_t)) != UINT32_MAX)
		OPn(parent, n_op++) = child;

	va_end(ap);

	return parent;
}

uint32_t
uc_append_op(struct uc_state *state, uint32_t a, uint32_t b)
{
	uint32_t tail_off, next_off;

	for (tail_off = a, next_off = OP_NEXT(tail_off);
	     next_off != 0;
	     tail_off = next_off, next_off = OP_NEXT(next_off))
		;

	OP_NEXT(tail_off) = b;

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
uc_new_double(double v)
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
uc_new_null(void)
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
	struct uc_op *op = json_object_get_userdata(v);

	json_object_put(op->tag.proto);
	free(ud);
}

struct json_object *
uc_new_object(struct json_object *proto) {
	struct json_object *val = xjs_new_object();
	struct uc_op *op = xalloc(sizeof(*op));

	op->val = val;
	op->type = T_LBRACE;
	op->tag.proto = json_object_get(proto);

	json_object_set_serializer(val, NULL, op, obj_free);

	return op->val;
}

static void
re_free(struct json_object *v, void *ud)
{
	struct uc_op *op = ud;

	regfree((regex_t *)op->tag.data);
	free(op);
}

static int
re_to_string(struct json_object *v, struct printbuf *pb, int level, int flags)
{
	bool strict = (level > 0) || (flags & JSON_C_TO_STRING_STRICT);
	struct uc_op *op = json_object_get_userdata(v);
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
uc_new_regexp(const char *source, bool icase, bool newline, bool global, char **err) {
	int cflags = REG_EXTENDED, res;
	struct uc_op *op;
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
	struct uc_op *op = ud;
	struct uc_function *fn = op->tag.data;

	json_object_put(fn->args);
	uc_release_scope(fn->parent_scope);

	free(op);
}

static int
func_to_string(struct json_object *v, struct printbuf *pb, int level, int flags)
{
	bool strict = (level > 0) || (flags & JSON_C_TO_STRING_STRICT), rest;
	struct uc_op *op = json_object_get_userdata(v);
	struct uc_function *fn = op->tag.data;
	size_t i, len;

	if (op->is_arrow)
		sprintbuf(pb, "%s(", strict ? "\"" : "");
	else
		sprintbuf(pb, "%sfunction%s%s(",
		          strict ? "\"" : "",
		          fn->name ? " " : "",
		          fn->name ? fn->name : "");

	if (fn->args) {
		len = json_object_array_length(fn->args);
		rest = (len > 1) && json_object_is_type(json_object_array_get_idx(fn->args, len - 1), json_type_null);

		for (i = 0; i < len - rest; i++) {
			sprintbuf(pb, "%s%s%s",
			          i ? ", " : "",
			          rest && i == len - 2 ? "..." : "",
			          json_object_get_string(json_object_array_get_idx(fn->args, i)));
		}
	}

	return sprintbuf(pb, ") %s{ ... }%s",
	                 op->is_arrow ? "=> " : "",
	                 strict ? "\"" : "");
}

struct json_object *
uc_new_func(struct uc_state *state, uint32_t decl, struct uc_scope *scope)
{
	struct json_object *val = xjs_new_object();
	uint32_t name_off, args_off, arg_off;
	struct uc_function *fn;
	struct uc_op *op;
	size_t sz;

	sz = ALIGN(sizeof(*op)) + ALIGN(sizeof(*fn));

	name_off = OPn(decl, 0);
	args_off = OPn(decl, 1);

	if (name_off)
		sz += ALIGN(json_object_get_string_len(OP_VAL(name_off)) + 1);

	op = xalloc(sz);

	fn = (void *)op + ALIGN(sizeof(*op));
	fn->entry = OPn(decl, 2);

	if (name_off)
		fn->name = strcpy((char *)fn + ALIGN(sizeof(*fn)), json_object_get_string(OP_VAL(name_off)));

	if (args_off) {
		fn->args = xjs_new_array();

		for (arg_off = args_off; arg_off != 0; arg_off = OP_NEXT(arg_off)) {
			json_object_array_add(fn->args, json_object_get(OP_VAL(arg_off)));

			/* if the last argument is a rest one (...arg), add extra null entry */
			if (OP_IS_ELLIP(arg_off)) {
				json_object_array_add(fn->args, NULL);
				break;
			}
		}
	}

	fn->source = state->function ? state->function->source : NULL;
	fn->parent_scope = uc_acquire_scope(scope);

	op->val = val;
	op->type = T_FUNC;
	op->is_arrow = (OP_TYPE(decl) == T_ARROW);
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
add_stacktrace(struct json_object *a, struct uc_function *function, size_t off) {
	struct json_object *o = xjs_new_object();
	size_t line = 1, rlen = 0, len;
	bool truncated = false;
	char buf[256];

	if (function->source->filename)
		json_object_object_add(o, "filename", xjs_new_string(function->source->filename));

	if (function->name)
		json_object_object_add(o, "function", xjs_new_string(function->name));

	if (function->source->fp) {
		fseek(function->source->fp, 0, SEEK_SET);

		while (fgets(buf, sizeof(buf), function->source->fp)) {
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
	}

	json_object_array_add(a, o);
}

__attribute__((format(printf, 3, 4))) struct json_object *
uc_new_exception(struct uc_state *s, uint32_t off, const char *fmt, ...)
{
	struct uc_callstack *callstack, *prevcall, here = {};
	struct json_object *a;
	struct uc_op *op;
	va_list ap;
	char *p;
	int len;

	op = xalloc(sizeof(*op));
	op->type = T_EXCEPTION;
	op->val = xjs_new_object();
	op->off = off;
	op->tag.data = s->function ? s->function->source : s->source;

	a = xjs_new_array();

	here.next = s->callstack;
	here.function = s->function;
	here.off = off;

	for (callstack = &here, prevcall = NULL; callstack != NULL;
	     prevcall = callstack, callstack = callstack->next)
		if (callstack->off && callstack->function && callstack->function->source &&
		    (!prevcall || callstack->function != prevcall->function || callstack->off != prevcall->off))
			add_stacktrace(a, callstack->function, callstack->off);

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
	struct uc_scope *sc = ud;

	if (sc->parent) {
		uc_release_scope(json_object_get_userdata(sc->parent));
		sc->parent = NULL;
	}

	sc->scope = NULL;
}

void
uc_release_scope(struct uc_scope *sc)
{
	if (sc->refs == 0)
		abort();

	sc->refs--;

	if (sc->refs == 0)
		json_object_put(sc->scope);
}

struct uc_scope *
uc_acquire_scope(struct uc_scope *sc)
{
	sc->refs++;

	return sc;
}

struct uc_scope *
uc_new_scope(struct uc_state *s, struct uc_scope *parent)
{
	struct uc_scope *sc;

	sc = xalloc(sizeof(*sc));
	sc->scope = xjs_new_object();

	if (parent)
		sc->parent = uc_acquire_scope(parent)->scope;

	json_object_set_userdata(sc->scope, sc, scope_free);

	sc->next = s->scopelist;
	s->scopelist = sc;

	return uc_acquire_scope(sc);
}

struct uc_scope *
uc_parent_scope(struct uc_scope *scope)
{
	return json_object_get_userdata(scope->parent);
}

static void
uc_reset(struct uc_state *s)
{
	json_object_put(s->exception);
	s->exception = NULL;

	free(s->lex.lookbehind);
	free(s->lex.buf);
	memset(&s->lex, 0, sizeof(s->lex));
}

void
uc_free(struct uc_state *s)
{
	struct uc_source *src, *src_next;
	struct uc_scope *sc, *sc_next;
	struct json_object *scj;
	size_t n;

	if (s) {
		json_object_put(s->ctx);

		for (n = 0; n < s->poolsize; n++)
			json_object_put(s->pool[n].val);

		free(s->pool);

		s->pool = NULL;
		s->poolsize = 0;

		uc_reset(s);

		json_object_put(s->rval);

		for (sc = s->scopelist; sc; sc = sc->next) {
			scj = sc->scope;
			sc->scope = NULL;
			json_object_put(scj);
		}

		for (sc = s->scopelist; sc; sc = sc_next) {
			sc_next = sc->next;
			free(sc);
		}

		for (src = s->sources; src; src = src_next) {
			src_next = src->next;

			if (src->fp)
				fclose(src->fp);

			free(src->filename);
			free(src);
		}
	}

	while (uc_ext_types_count > 0)
		json_object_put(uc_ext_types[--uc_ext_types_count].proto);

	free(uc_ext_types);
	free(s);
}

struct json_object *
uc_parse(struct uc_state *state, FILE *fp)
{
	void *pParser;
	uint32_t off;

	uc_reset(state);

	pParser = ParseAlloc(xalloc);

	while (state->lex.state != UT_LEX_EOF) {
		off = uc_get_token(state, fp);

		if (state->exception)
			goto out;

		if (off)
			Parse(pParser, OP_TYPE(off), off, state);

		if (state->exception)
			goto out;
	}

	Parse(pParser, 0, 0, state);

out:
	ParseFree(pParser, free);

	return state->exception;
}

bool
uc_register_extended_type(const char *name, struct json_object *proto, void (*freefn)(void *))
{
	uc_ext_types = xrealloc(uc_ext_types, (uc_ext_types_count + 1) * sizeof(*uc_ext_types));
	uc_ext_types[uc_ext_types_count].name = name;
	uc_ext_types[uc_ext_types_count].free = freefn;
	uc_ext_types[uc_ext_types_count].proto = proto;
	uc_ext_types_count++;

	return true;
}

static int
uc_extended_type_to_string(struct json_object *v, struct printbuf *pb, int level, int flags)
{
	bool strict = (level > 0) || (flags & JSON_C_TO_STRING_STRICT);
	struct uc_op *op = json_object_get_userdata(v);
	struct uc_extended_type *et;

	if (!op)
		return 0;

	et = &uc_ext_types[op->tag.type - 1];

	return sprintbuf(pb, "%s<%s %p>%s",
	                 strict ? "\"" : "",
	                 et->name, op->tag.data,
	                 strict ? "\"" : "");
}

static void
uc_extended_type_free(struct json_object *v, void *ud)
{
	struct uc_op *op = json_object_get_userdata(v);
	struct uc_extended_type *et;

	if (!op)
		return;

	et = &uc_ext_types[op->tag.type - 1];

	if (et->free && op->tag.data)
		et->free(op->tag.data);

	json_object_put(op->tag.proto);
	free(ud);
}

struct json_object *
uc_set_extended_type(struct json_object *v, const char *name, void *data)
{
	struct uc_extended_type *et = NULL;
	struct uc_op *op;
	size_t n;

	for (n = 0; n < uc_ext_types_count; n++) {
		if (!strcmp(name, uc_ext_types[n].name)) {
			et = &uc_ext_types[n];
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

	json_object_set_serializer(op->val, uc_extended_type_to_string, op, uc_extended_type_free);

	return op->val;
}

void **
uc_get_extended_type(struct json_object *v, const char *name)
{
	struct uc_op *op = json_object_get_userdata(v);
	size_t n = op ? op->tag.type : 0;
	struct uc_extended_type *et;

	if (!op || op->type != T_RESSOURCE || n == 0 || n > uc_ext_types_count)
		return NULL;

	et = &uc_ext_types[n - 1];

	if (name && strcmp(et->name, name))
		return NULL;

	return &op->tag.data;
}
