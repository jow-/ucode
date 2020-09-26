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
	struct ut_op *newop, *pool;
	uint32_t child;
	int n_op = 0;
	va_list ap;

	if ((s->poolsize + 1) == UINT32_MAX) {
		fprintf(stderr, "Program too large\n");
		exit(127);
	}

	pool = realloc(s->pool, (s->poolsize + 1) * sizeof(*newop));

	if (!pool) {
		fprintf(stderr, "Out of memory\n");
		exit(127);
	}

	newop = &pool[s->poolsize];
	memset(newop, 0, sizeof(*newop));

	newop->is_first = !s->poolsize;
	newop->is_op = true;
	newop->off = s->off;
	newop->type = type;
	newop->val = val;

	va_start(ap, val);

	while (n_op < ARRAY_SIZE(newop->tree.operand) && (child = va_arg(ap, uint32_t)) != UINT32_MAX)
		newop->tree.operand[n_op++] = child;

	va_end(ap);

	s->pool = pool;
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
	struct json_object *val = json_object_new_object();
	struct ut_op *op;

	if (!val)
		return NULL;

	op = calloc(1, sizeof(*op));

	if (!op) {
		json_object_put(val);

		return NULL;
	}

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

	s = json_object_new_string((char *)op + sizeof(*op) + sizeof(regex_t));

	if (s) {
		if (strict) {
			for (p = json_object_to_json_string(s) + 1, len = strlen(p) - 1; len > 0; len--, p++)
				sprintbuf(pb, "%c", *p);
		}
		else {
			sprintbuf(pb, "%s", json_object_get_string(s));
		}
	}
	else {
		sprintbuf(pb, "...");
	}

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

	op = calloc(1, sizeof(*op) + sizeof(*re) + strlen(source) + 1);

	if (!op)
		return NULL;

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
		*err = calloc(1, len);

		if (*err)
			regerror(res, re, *err, len);

		free(op);

		return NULL;
	}

	//op->val = json_object_new_string(source);
	op->val = json_object_new_object();

	if (!op->val) {
		free(op);

		return NULL;
	}

	json_object_set_serializer(op->val, re_to_string, op, re_free);

	return op->val;
}

static int
func_to_string(struct json_object *v, struct printbuf *pb, int level, int flags)
{
	bool strict = (level > 0) || (flags & JSON_C_TO_STRING_STRICT);
	struct ut_op *op = json_object_get_userdata(v);
	struct ut_op *base, *decl, *name, *args, *arg;

	if (!op->tag.data)
		return 0;

	/* find start of operand array */
	for (decl = op->tag.data, base = decl; base && !base->is_first; base--)
		;

	name = base + (decl->tree.operand[0] ? decl->tree.operand[0] - 1 : 0);
	args = base + (decl->tree.operand[1] ? decl->tree.operand[1] - 1 : 0);

	sprintbuf(pb, "%sfunction%s%s(",
	          strict ? "\"" : "",
	          (name != base) ? " " : "",
	          (name != base) ? json_object_get_string(name->val) : "");

	for (arg = args; arg != base; arg = base + (arg->tree.next ? arg->tree.next - 1 : 0))
		sprintbuf(pb, "%s%s",
		          (arg != args) ? ", " : "",
		          json_object_get_string(arg->val));

	return sprintbuf(pb, ") { ... }%s", strict ? "\"" : "");
}

struct json_object *
ut_new_func(struct ut_op *decl)
{
	struct json_object *val = json_object_new_object();
	struct ut_op *op;

	if (!val)
		return NULL;

	op = calloc(1, sizeof(*op));

	if (!op) {
		json_object_put(val);

		return NULL;
	}

	op->val = val;
	op->type = T_FUNC;
	op->tag.data = decl;

	json_object_set_serializer(val, func_to_string, op, obj_free);

	return op->val;
}

static void
ut_reset(struct ut_state *s)
{
	s->semicolon_emitted = false;
	s->start_tag_seen = false;
	s->blocktype = UT_BLOCK_NONE;
	s->off = 0;

	if (s->error.code == UT_ERROR_EXCEPTION)
		json_object_put(s->error.info.exception);

	memset(&s->error, 0, sizeof(s->error));
}

void
ut_free(struct ut_state *s)
{
	size_t n;

	if (s) {
		json_object_put(s->ctx);

		while (s->stack.off > 0)
			json_object_put(s->stack.scope[--s->stack.off]);

		free(s->stack.scope);

		for (n = 0; n < s->poolsize; n++)
			json_object_put(s->pool[n].val);

		free(s->pool);

		s->pool = NULL;
		s->poolsize = 0;

		ut_reset(s);
	}

	while (ut_ext_types_count > 0)
		json_object_put(ut_ext_types[--ut_ext_types_count].proto);

	free(ut_ext_types);
	free(s);
}

enum ut_error_type
ut_parse(struct ut_state *s, const char *expr)
{
	int len = strlen(expr);
	const char *ptr = expr;
	struct ut_op *op;
	void *pParser;
	int mlen = 0;
	uint32_t off;

	if (!s)
		return UT_ERROR_OUT_OF_MEMORY;

	ut_reset(s);

	pParser = ParseAlloc(malloc);

	if (!pParser)
		return UT_ERROR_OUT_OF_MEMORY;

	while (len > 0) {
		off = ut_get_token(s, ptr, &mlen);
		op = ut_get_op(s, off);

		if (mlen < 0) {
			s->error.code = -mlen;
			goto out;
		}

		if (op)
			Parse(pParser, op->type, off, s);

		if (s->error.code)
			goto out;

		len -= mlen;
		ptr += mlen;
	}

	Parse(pParser, 0, 0, s);

out:
	ParseFree(pParser, free);

	return s->error.code;
}

bool
ut_register_extended_type(const char *name, struct json_object *proto, void (*freefn)(void *))
{
	struct ut_extended_type *tmp;

	tmp = realloc(ut_ext_types, (ut_ext_types_count + 1) * sizeof(*tmp));

	if (!tmp)
		return false;

	ut_ext_types = tmp;
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

	op = calloc(1, sizeof(*op));

	if (!op)
		return NULL;

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
