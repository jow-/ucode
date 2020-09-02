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
#include "lexer.h"
#include "parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>

static size_t ut_ext_types_count = 0;
static struct ut_extended_type *ut_ext_types = NULL;

struct ut_opcode *
ut_new_op(struct ut_state *s, int type, struct json_object *val, ...)
{
	struct ut_opcode *newop, *child;
	int n_op = 0;
	va_list ap;

	newop = calloc(1, sizeof(*newop));

	if (!newop) {
		fprintf(stderr, "Out of memory\n");
		exit(127);
	}

	newop->off = s->off;
	newop->type = type;
	newop->val = val;

	va_start(ap, val);

	while ((child = va_arg(ap, void *)) != (void *)1)
		if (n_op < sizeof(newop->operand) / sizeof(newop->operand[0]))
			newop->operand[n_op++] = child;

	va_end(ap);

	newop->next = s->pool;
	s->pool = newop;

	return newop;
}

struct ut_opcode *
ut_wrap_op(struct ut_opcode *parent, ...)
{
	struct ut_opcode *child;
	int n_op = 0;
	va_list ap;

	va_start(ap, parent);

	while ((child = va_arg(ap, void *)) != (void *)1)
		if (n_op < sizeof(parent->operand) / sizeof(parent->operand[0]))
			parent->operand[n_op++] = child;

	va_end(ap);

	return parent;
}

struct ut_opcode *
ut_append_op(struct ut_opcode *a, struct ut_opcode *b)
{
	struct ut_opcode *tail = a;

	while (tail->sibling)
		tail = tail->sibling;

	tail->sibling = b;

	return a;
}

static int
double_rounded_to_string(struct json_object *v, struct printbuf *pb, int level, int flags)
{
	double d = json_object_get_double(v);

	if (isnan(d))
		return sprintbuf(pb, level ? "\"NaN\"" : "NaN");

	if (d == INFINITY)
		return sprintbuf(pb, level ? "1e309" : "Infinity");

	if (d == -INFINITY)
		return sprintbuf(pb, level ? "-1e309" : "-Infinity");

	return sprintbuf(pb, "%g", d);
}

struct json_object *
json_object_new_double_rounded(double v)
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
json_object_new_null_obj(void) {
	struct json_object *d = json_object_new_boolean(false);

	json_object_set_serializer(d, null_obj_to_string, NULL, NULL);

	return d;
}

static int
func_to_string(struct json_object *v, struct printbuf *pb, int level, int flags)
{
	struct ut_opcode *op = json_object_get_userdata(v);
	struct ut_opcode *args = op ? op->operand[1] : NULL;
	struct json_object *name = (op && op->operand[0]) ? op->operand[0]->val : NULL;

	sprintbuf(pb, "%sfunction%s%s(",
		level ? "\"" : "",
		name ? " " : "",
		name ? json_object_get_string(name) : "");

	while (args) {
		sprintbuf(pb, "%s%s",
			(args != op->operand[1]) ? ", " : "",
			json_object_get_string(args->val));

		args = args->sibling;
	}

	return sprintbuf(pb, ") { ... }%s",
		level ? "\"" : "");
}

struct ut_opcode *
ut_new_func(struct ut_state *s, struct ut_opcode *name, struct ut_opcode *args, struct ut_opcode *body)
{
	struct ut_opcode *op = ut_new_op(s, T_FUNC, json_object_new_boolean(0), name, args, body, (void *)1);

	json_object_set_serializer(op->val, func_to_string, op, NULL);

	return op;
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
	struct ut_opcode *op, *tmp;

	if (s) {
		while (s->stack.off > 0)
			json_object_put(s->stack.scope[--s->stack.off]);

		free(s->stack.scope);

		for (op = s->pool; op;) {
			tmp = op->next;

			json_object_put(op->val);

			free(op);
			op = tmp;
		}

		ut_reset(s);
	}

	free(ut_ext_types);
	free(s);
}

enum ut_error_type
ut_parse(struct ut_state *s, const char *expr)
{
	int len = strlen(expr);
	const char *ptr = expr;
	struct ut_opcode *op;
	void *pParser;
	int mlen = 0;

	if (!s)
		return UT_ERROR_OUT_OF_MEMORY;

	ut_reset(s);

	pParser = ParseAlloc(malloc);

	if (!pParser)
		return UT_ERROR_OUT_OF_MEMORY;

	while (len > 0) {
		op = ut_get_token(s, ptr, &mlen);

		if (mlen < 0) {
			s->error.code = -mlen;
			goto out;
		}

		if (op)
			Parse(pParser, op->type, op, s);

		if (s->error.code)
			goto out;

		len -= mlen;
		ptr += mlen;
	}

	Parse(pParser, 0, NULL, s);

out:
	ParseFree(pParser, free);

	return s->error.code;
}

bool
ut_register_extended_type(const char *name, void (*freefn)(void *))
{
	struct ut_extended_type *tmp;

	tmp = realloc(ut_ext_types, (ut_ext_types_count + 1) * sizeof(*tmp));

	if (!tmp)
		return false;

	ut_ext_types = tmp;
	ut_ext_types[ut_ext_types_count].name = name;
	ut_ext_types[ut_ext_types_count].free = freefn;
	ut_ext_types_count++;

	return true;
}

static int
ut_extended_type_to_string(struct json_object *v, struct printbuf *pb, int level, int flags)
{
	struct ut_tagvalue *tag = json_object_get_userdata(v);
	struct ut_extended_type *et;

	if (!tag)
		return 0;

	et = &ut_ext_types[tag->tagtype - 1];

	return sprintbuf(pb, "%s<%s %p>%s", level ? "\"" : "", et->name, tag->data, level ? "\"" : "");
}

static void
ut_extended_type_free(struct json_object *v, void *ud)
{
	struct ut_tagvalue *tag = json_object_get_userdata(v);
	struct ut_extended_type *et;

	if (!tag)
		return;

	et = &ut_ext_types[tag->tagtype - 1];

	if (et->free)
		et->free(tag->data);

	json_object_put(tag->proto);
	free(ud);
}

struct json_object *
ut_set_extended_type(struct ut_state *s, struct json_object *v, struct json_object *proto, const char *name, void *data)
{
	struct ut_extended_type *et = NULL;
	struct ut_tagvalue *tag;
	size_t n;

	for (n = 0; n < ut_ext_types_count; n++) {
		if (!strcmp(name, ut_ext_types[n].name)) {
			et = &ut_ext_types[n];
			break;
		}
	}

	if (!et)
		return NULL;

	tag = calloc(1, sizeof(*tag));

	if (!tag)
		return NULL;

	tag->val = v;
	tag->type = T_RESSOURCE;
	tag->proto = json_object_get(proto);
	tag->tagtype = n + 1;
	tag->data = data;

	json_object_set_serializer(tag->val, ut_extended_type_to_string, tag, ut_extended_type_free);

	return tag->val;
}

void **
ut_get_extended_type(struct json_object *v, const char *name)
{
	struct ut_tagvalue *tag = json_object_get_userdata(v);
	size_t n = tag ? tag->tagtype : 0;
	struct ut_extended_type *et;

	if (!tag || tag->type != T_RESSOURCE || n == 0 || n > ut_ext_types_count)
		return NULL;

	et = &ut_ext_types[n - 1];

	if (name && strcmp(et->name, name))
		return NULL;

	return &tag->data;
}
