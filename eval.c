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

#include "lexer.h"
#include "parser.h"
#include "eval.h"
#include "lib.h"

#include <math.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <regex.h>

bool
ut_val_is_truish(struct json_object *val)
{
	struct ut_op *tag = json_object_get_userdata(val);
	double d;

	switch (tag ? tag->type : 0) {
	case T_EXCEPTION:
		return false;

	default:
		switch (json_object_get_type(val)) {
		case json_type_int:
			return (json_object_get_int64(val) != 0);

		case json_type_double:
			d = json_object_get_double(val);

			return (d != 0 && !isnan(d));

		case json_type_boolean:
			return (json_object_get_boolean(val) != false);

		case json_type_string:
			return (json_object_get_string_len(val) > 0);

		case json_type_array:
		case json_type_object:
			return true;

		default:
			return false;
		}
	}
}

enum json_type
ut_cast_number(struct json_object *v, int64_t *n, double *d)
{
	bool is_double = false;
	const char *s;
	char *e;

	*d = 0.0;
	*n = 0;

	switch (json_object_get_type(v)) {
	case json_type_int:
		*n = json_object_get_int64(v);

		return json_type_int;

	case json_type_double:
		*d = json_object_get_double(v);

		return json_type_double;

	case json_type_null:
		return json_type_int;

	case json_type_boolean:
		*n = json_object_get_boolean(v) ? 1 : 0;

		return json_type_int;

	case json_type_string:
		s = json_object_get_string(v);

		while (isspace(*s))
			s++;

		if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X') && isxdigit(s[2])) {
			*n = strtoll(s, &e, 16);
		}
		else if (s[0] == '0' && isdigit(s[2])) {
			*n = strtoll(s, &e, 8);
		}
		else {
			*n = strtoll(s, &e, 10);

			if (*e == '.') {
				*d = strtod(s, &e);
				is_double = (e > s);
			}
		}

		while (isspace(*e))
			e++;

		if (*e) {
			*d = NAN;

			return json_type_double;
		}

		if (is_double)
			return json_type_double;

		return json_type_int;

	default:
		*d = NAN;

		return json_type_double;
	}
}

static struct json_object *
ut_execute_op(struct ut_state *state, uint32_t off);

static struct json_object *
ut_execute_list(struct ut_state *state, uint32_t off);

static char *
ut_ref_to_str(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct ut_op *op2 = ut_get_child(state, off, 1);
	const char *l;
	char *s, *p;

	switch (op ? op->type : 0) {
	case T_DOT:
		s = ut_ref_to_str(state, op->tree.operand[0]);
		l = ((op2 ? op2->type : 0) == T_LABEL) ? json_object_get_string(op2->val) : "???";

		if (asprintf(&p, "%s.%s", s ? s : "(...)", l) == -1)
			p = NULL;

		free(s);

		return p;

	case T_LBRACK:
		if (!op->is_postfix)
			return NULL;

		/* fall through */

	case T_LPAREN:
		s = ut_ref_to_str(state, op->tree.operand[0]);

		switch (op2 ? op2->type : 0) {
		case T_STRING:
			l = json_object_to_json_string_ext(op2->val, JSON_C_TO_STRING_NOSLASHESCAPE);
			break;

		case T_NUMBER:
		case T_LABEL:
		case T_BOOL:
			l = json_object_get_string(op2->val);
			break;

		default:
			l = "...";
		}

		if (asprintf(&p, "%s%c%s%c", s ? s : "(...)",
		             (op->type == T_LPAREN) ? '(' : '[', l,
		             (op->type == T_LPAREN) ? ')' : ']') == -1)
			p = NULL;

		free(s);

		return p;

	case T_LABEL:
		return strdup(json_object_get_string(op->val));

	default:
		return NULL;
	}
}

static struct json_object *
ut_getref(struct ut_state *state, uint32_t off, struct json_object **key)
{
	struct ut_op *op = ut_get_op(state, off);
	uint32_t off1 = op ? op->tree.operand[0] : 0;
	uint32_t off2 = op ? op->tree.operand[1] : 0;
	struct ut_scope *sc, *next;
	struct json_object *val;

	if (key)
		*key = NULL;

	if (op && op->type == T_DOT) {
		if (key)
			*key = off2 ? json_object_get(ut_get_op(state, off2)->val) : NULL;

		return ut_execute_op(state, off1);
	}
	else if (op && op->type == T_LBRACK && op->is_postfix) {
		if (key) {
			val = off2 ? ut_execute_op(state, off2) : NULL;

			if (ut_is_type(val, T_EXCEPTION))
				return val;

			*key = val;
		}

		return ut_execute_op(state, off1);
	}
	else if (op && op->type == T_LABEL) {
		sc = state->scope;

		while (true) {
			if (json_object_object_get_ex(sc->scope, json_object_get_string(op->val), NULL))
				break;

			next = ut_parent_scope(sc);

			if (!next) {
				if (state->strict_declarations) {
					return ut_new_exception(state, op->off,
					                        "Reference error: access to undeclared variable %s",
					                        json_object_get_string(op->val));
				}

				break;
			}

			sc = next;
		}

		if (key)
			*key = json_object_get(op->val);

		return json_object_get(sc->scope);
	}
	else {
		if (key)
			*key = NULL;

		return NULL;
	}
}

static struct json_object *
ut_getref_required(struct ut_state *state, uint32_t off, struct json_object **key)
{
	struct ut_op *op1 = ut_get_child(state, off, 0);
	struct json_object *scope, *skey, *rv;
	char *lhs;

	scope = ut_getref(state, off, &skey);

	if (!json_object_is_type(scope, json_type_array) &&
		!json_object_is_type(scope, json_type_object)) {
		if (!ut_is_type(scope, T_EXCEPTION)) {
			lhs = op1 ? ut_ref_to_str(state, ut_get_off(state, op1)) : NULL;

			if (lhs) {
				rv = ut_new_exception(state, op1->off, "Type error: `%s` is %s",
				                      lhs, scope ? "not an array or object" : "null");
				free(lhs);
			}
			else {
				rv = ut_new_exception(state, op1->off, "Type error: left-hand side is not an array or object");
			}

			json_object_put(scope);
		}
		else {
			rv = scope;
		}

		json_object_put(skey);

		*key = NULL;
		return rv;
	}

	*key = skey;
	return scope;
}

static struct json_object *
ut_getproto(struct json_object *obj)
{
	struct ut_op *op = json_object_get_userdata(obj);

	if (!op || (op->type != T_LBRACE && op->type <= __T_MAX) || !op->val)
		return NULL;

	return op->tag.proto;
}

static struct json_object *
ut_getval(struct json_object *scope, struct json_object *key)
{
	struct json_object *o, *v;
	int64_t idx;
	double d;

	if (!key)
		return NULL;

	if (json_object_is_type(scope, json_type_array)) {
		/* only consider doubles with integer values as array keys */
		if (json_object_is_type(key, json_type_double)) {
			d = json_object_get_double(key);

			if ((double)(int64_t)(d) != d)
				return NULL;

			idx = (int64_t)d;
		}
		else {
			errno = 0;
			idx = json_object_get_int64(key);

			if (errno != 0)
				return NULL;
		}

		return json_object_get(json_object_array_get_idx(scope, idx));
	}

	for (o = scope; o; o = ut_getproto(o)) {
		if (!json_object_is_type(o, json_type_object))
			continue;

		if (json_object_object_get_ex(o, key ? json_object_get_string(key) : "null", &v))
			return json_object_get(v);
	}

	return NULL;
}

static struct json_object *
ut_setval(struct json_object *scope, struct json_object *key, struct json_object *val)
{
	int64_t idx;

	if (!key)
		return NULL;

	if (json_object_is_type(scope, json_type_array)) {
		errno = 0;
		idx = json_object_get_int64(key);

		if (errno != 0)
			return NULL;

		if (json_object_array_put_idx(scope, idx, val))
			return NULL;

		return json_object_get(val);
	}

	if (json_object_object_add(scope, key ? json_object_get_string(key) : "null", val))
		return NULL;

	return json_object_get(val);
}

static struct json_object *
ut_execute_assign(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	uint32_t label = op ? op->tree.operand[0] : 0;
	uint32_t value = op ? op->tree.operand[1] : 0;
	struct json_object *scope, *key, *val;

	scope = ut_getref_required(state, label, &key);

	if (!key)
		return scope;

	val = ut_execute_op(state, value);

	if (!ut_is_type(val, T_EXCEPTION))
		ut_setval(scope, key, val);

	json_object_put(scope);
	json_object_put(key);

	return val;
}

static struct json_object *
ut_execute_local(struct ut_state *state, uint32_t off)
{
	struct ut_op *as = ut_get_child(state, off, 0);
	struct json_object *val, *rv = NULL;
	struct ut_op *label;

	while (as) {
		label = ut_get_op(state, as->tree.operand[0]);

		if (label) {
			val = as->tree.operand[1] ? ut_execute_op(state, as->tree.operand[1]) : NULL;

			if (ut_is_type(val, T_EXCEPTION))
				return val;

			rv = ut_setval(state->scope->scope, label->val, val);
		}

		as = ut_get_op(state, as->tree.next);
	}

	return rv;
}

static struct json_object *
ut_execute_op_sequence(struct ut_state *state, uint32_t off);

static bool
ut_test_condition(struct ut_state *state, uint32_t off)
{
	struct json_object *val = ut_execute_op_sequence(state, off);
	bool istrue = ut_val_is_truish(val);

	json_object_put(val);

	return istrue;
}

static struct json_object *
ut_execute_if(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	uint32_t cond = op ? op->tree.operand[0] : 0;
	uint32_t Then = op ? op->tree.operand[1] : 0;
	uint32_t Else = op ? op->tree.operand[2] : 0;

	if (ut_test_condition(state, cond))
		return ut_execute_op_sequence(state, Then);
	else if (Else)
		return ut_execute_op_sequence(state, Else);

	return NULL;
}

static struct json_object *
ut_execute_for(struct ut_state *state, uint32_t off)
{
	struct json_object *scope, *val, *item, *rv = NULL;
	struct ut_op *loop = ut_get_op(state, off);
	struct ut_op *init = ut_get_child(state, off, 0);
	struct ut_op *test = ut_get_child(state, off, 1);
	struct ut_op *incr = ut_get_child(state, off, 2);
	struct ut_op *body = ut_get_child(state, off, 3);
	struct ut_op *ivar, *tag;
	size_t arridx, arrlen;
	bool local = false;

	/* for (x in ...) loop variant */
	if (loop->is_for_in) {
		if (init->type == T_LOCAL) {
			local = true;
			init = ut_get_op(state, init->tree.operand[0]);
		}

		if (init->type != T_IN)
			return ut_new_exception(state, init->off,
			                        "Syntax error: missing ';' after for loop initializer");

		ivar = ut_get_op(state, init->tree.operand[0]);

		if (!ivar || ivar->type != T_LABEL)
			return ut_new_exception(state, init->off,
			                        "Syntax error: invalid for-in left-hand side");

		val = ut_execute_op(state, init->tree.operand[1]);

		if (ut_is_type(val, T_EXCEPTION))
			return val;

		scope = local ? state->scope->scope : ut_getref(state, ut_get_off(state, ivar), NULL);

		if (ut_is_type(scope, T_EXCEPTION)) {
			json_object_put(val);

			return scope;
		}

		if (json_object_is_type(val, json_type_array)) {
			for (arridx = 0, arrlen = json_object_array_length(val);
			     arridx < arrlen; arridx++) {
				item = json_object_array_get_idx(val, arridx);

				ut_setval(scope, ivar->val, item);
				json_object_put(rv);

				rv = ut_execute_op_sequence(state, ut_get_off(state, body));
				tag = json_object_get_userdata(rv);

				switch (tag ? tag->type : 0) {
				case T_RETURN:
				case T_EXCEPTION:
					json_object_put(val);

					return rv;

				case T_BREAK:
					json_object_put(val);
					json_object_put(rv);

					return NULL;
				}
			}
		}
		else if (json_object_is_type(val, json_type_object)) {
			json_object_object_foreach(val, key, item) {
				ut_setval(scope, ivar->val, xjs_new_string(key));
				json_object_put(rv);

				rv = ut_execute_op_sequence(state, ut_get_off(state, body));
				tag = json_object_get_userdata(rv);

				switch (tag ? tag->type : 0) {
				case T_RETURN:
				case T_EXCEPTION:
					json_object_put(val);

					return rv;

				case T_BREAK:
					json_object_put(val);
					json_object_put(rv);

					return NULL;
				}
			}
		}

		json_object_put(val);
		json_object_put(rv);

		return NULL;
	}

	if (init) {
		val = ut_execute_op_sequence(state, ut_get_off(state, init));

		if (ut_is_type(val, T_EXCEPTION))
			return val;

		json_object_put(val);
	}

	while (test ? ut_test_condition(state, ut_get_off(state, test)) : true) {
		json_object_put(rv);

		rv = ut_execute_op_sequence(state, ut_get_off(state, body));
		tag = json_object_get_userdata(rv);

		switch (tag ? tag->type : 0) {
		case T_RETURN:
		case T_EXCEPTION:
			return rv;

		case T_BREAK:
			json_object_put(rv);

			return NULL;
		}

		if (incr) {
			val = ut_execute_op_sequence(state, ut_get_off(state, incr));

			if (ut_is_type(val, T_EXCEPTION)) {
				json_object_put(rv);

				return val;
			}

			json_object_put(val);
		}
	}

	json_object_put(rv);

	return NULL;
}

static struct json_object *
ut_execute_while(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	uint32_t test = op ? op->tree.operand[0] : 0;
	uint32_t body = op ? op->tree.operand[1] : 0;
	struct json_object *v, *rv = NULL;
	struct ut_op *tag = NULL;
	bool cond;

	while (1) {
		json_object_put(rv);

		v = test ? ut_execute_op_sequence(state, test) : NULL;
		cond = test ? ut_val_is_truish(v) : true;

		if (ut_is_type(v, T_EXCEPTION))
			return v;

		json_object_put(v);

		if (!cond)
			return NULL;

		rv = ut_execute_op_sequence(state, body);
		tag = json_object_get_userdata(rv);

		switch (tag ? tag->type : 0) {
		case T_RETURN:
		case T_EXCEPTION:
			return rv;

		case T_BREAK:
			json_object_put(rv);

			return NULL;
		}
	}

	json_object_put(rv);

	return NULL;
}

static struct json_object *
ut_execute_and_or(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *val = NULL;
	int i;

	for (i = 0; i < ARRAY_SIZE(op->tree.operand) && op->tree.operand[i]; i++) {
		json_object_put(val);

		val = ut_execute_op(state, op->tree.operand[i]);

		if (ut_is_type(val, T_EXCEPTION))
			break;

		if (ut_val_is_truish(val) == (op->type == T_OR))
			break;
	}

	return val;
}

bool
ut_cmp(int how, struct json_object *v1, struct json_object *v2)
{
	enum json_type t1 = json_object_get_type(v1);
	enum json_type t2 = json_object_get_type(v2);
	int64_t n1, n2, delta;
	double d1, d2;

	if (t1 == json_type_string && t2 == json_type_string) {
		delta = strcmp(json_object_get_string(v1), json_object_get_string(v2));
	}
	else {
		if ((t1 == json_type_array && t2 == json_type_array) ||
		    (t1 == json_type_object && t2 == json_type_object))	{
			delta = (void *)v1 - (void *)v2;
		}
		else {
			t1 = ut_cast_number(v1, &n1, &d1);
			t2 = ut_cast_number(v2, &n2, &d2);

			if (t1 == json_type_double || t2 == json_type_double) {
				d1 = (t1 == json_type_double) ? d1 : (double)n1;
				d2 = (t2 == json_type_double) ? d2 : (double)n2;

				if (d1 == d2)
					delta = 0;
				else if (d1 < d2)
					delta = -1;
				else
					delta = 1;
			}
			else {
				delta = n1 - n2;
			}
		}
	}

	switch (how) {
	case T_LT:
		return (delta < 0);

	case T_LE:
		return (delta <= 0);

	case T_GT:
		return (delta > 0);

	case T_GE:
		return (delta >= 0);

	case T_EQ:
		return (delta == 0);

	case T_NE:
		return (delta != 0);

	default:
		return false;
	}
}

static struct json_object *
_ut_get_operands(struct ut_state *state, struct ut_op *op, size_t n, struct json_object **v)
{
	struct json_object *ctx = NULL;
	struct ut_op *child;
	size_t i, j;

	for (i = 0; i < n; i++) {
		child = op ? ut_get_op(state, op->tree.operand[i]) : NULL;

		if (child && child->is_list)
			v[i] = ut_execute_list(state, ut_get_off(state, child));
		else if (child)
			v[i] = ut_execute_op(state, ut_get_off(state, child));
		else
			v[i] = NULL;

		if (i == 0)
			ctx = json_object_get(state->ctx);

		if (ut_is_type(v[i], T_EXCEPTION)) {
			json_object_put(ctx);

			for (j = 0; j < i; j++)
				json_object_put(v[j]);

			return v[i];
		}
	}

	json_object_put(state->ctx);
	state->ctx = ctx;

	return NULL;
}

#define ut_get_operands(state, op, vals) \
	do { \
		struct json_object *ex = _ut_get_operands(state, op, ARRAY_SIZE(vals), vals); \
		if (ex) return ex; \
	} while(0)

static struct json_object *
ut_execute_rel(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *v[2], *rv;

	ut_get_operands(state, op, v);

	rv = xjs_new_boolean(ut_cmp(op->type, v[0], v[1]));

	json_object_put(v[0]);
	json_object_put(v[1]);

	return rv;
}

static bool
ut_eq(struct json_object *v1, struct json_object *v2)
{
	struct ut_op *tag1 = json_object_get_userdata(v1);
	struct ut_op *tag2 = json_object_get_userdata(v2);
	enum json_type t1 = json_object_get_type(v1);
	enum json_type t2 = json_object_get_type(v2);

	if ((tag1 ? tag1->type : 0) != (tag2 ? tag2->type : 0))
		return false;

	if (t1 != t2)
		return false;

	switch (t1) {
	case json_type_array:
	case json_type_object:
		return (v1 == v2);

	case json_type_boolean:
		return (json_object_get_boolean(v1) == json_object_get_boolean(v2));

	case json_type_double:
		if (isnan(json_object_get_double(v1)) || isnan(json_object_get_double(v2)))
			return false;

		return (json_object_get_double(v1) == json_object_get_double(v2));

	case json_type_int:
		return (json_object_get_int64(v1) == json_object_get_int64(v2));

	case json_type_string:
		return !strcmp(json_object_get_string(v1), json_object_get_string(v2));

	case json_type_null:
		return true;
	}

	return false;
}

static struct json_object *
ut_execute_equality(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *v[2], *rv;
	bool equal = false;

	ut_get_operands(state, op, v);

	equal = ut_eq(v[0], v[1]);
	rv = xjs_new_boolean((op->type == T_EQS) ? equal : !equal);

	json_object_put(v[0]);
	json_object_put(v[1]);

	return rv;
}

static struct json_object *
ut_execute_in(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *v[2], *item;
	size_t arrlen, arridx;
	bool found = false;
	const char *key;

	ut_get_operands(state, op, v);

	if (json_object_is_type(v[1], json_type_array)) {
		for (arridx = 0, arrlen = json_object_array_length(v[1]);
		     arridx < arrlen; arridx++) {
			item = json_object_array_get_idx(v[1], arridx);

			if (ut_cmp(T_EQ, v[0], item)) {
				found = true;
				break;
			}
		}
	}
	else if (json_object_is_type(v[1], json_type_object)) {
		key = v[0] ? json_object_get_string(v[0]) : "null";
		found = json_object_object_get_ex(v[1], key, NULL);
	}

	json_object_put(v[0]);
	json_object_put(v[1]);

	return xjs_new_boolean(found);
}

static struct json_object *
ut_execute_inc_dec(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *val, *nval, *scope, *key;
	uint32_t label = op ? op->tree.operand[0] : 0;
	int64_t n;
	double d;

	scope = ut_getref_required(state, label, &key);

	if (!key)
		return scope;

	val = ut_getval(scope, key);

	json_object_put(scope);
	json_object_put(key);

	if (ut_cast_number(val, &n, &d) == json_type_double)
		nval = ut_new_double(d + (op->type == T_INC ? 1.0 : -1.0));
	else
		nval = xjs_new_int64(n + (op->type == T_INC ? 1 : -1));

	json_object_put(ut_setval(scope, key, nval));

	/* postfix inc/dec, return old val */
	if (op->is_postfix)
		return val;

	json_object_put(val);

	return json_object_get(nval);
}

static struct json_object *
ut_execute_list(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *val, *arr = xjs_new_array();

	while (op) {
		val = ut_execute_op(state, ut_get_off(state, op));

		if (ut_is_type(val, T_EXCEPTION)) {
			json_object_put(arr);

			return val;
		}

		json_object_array_add(arr, val);
		op = ut_get_op(state, op->tree.next);
	}

	return arr;
}

static struct json_object *
ut_execute_object(struct ut_state *state, uint32_t off)
{
	struct json_object *v, *obj = ut_new_object(NULL);
	struct ut_op *key, *val;

	for (key = ut_get_child(state, off, 0), val = ut_get_op(state, key ? key->tree.next : 0);
	     key != NULL && val != NULL;
	     key = ut_get_op(state, val->tree.next), val = ut_get_op(state, key ? key->tree.next : 0)) {
		v = ut_execute_op(state, ut_get_off(state, val));

		if (ut_is_type(v, T_EXCEPTION)) {
			json_object_put(obj);

			return v;
		}

		json_object_object_add(obj, json_object_get_string(key->val), v);
	}

	return obj;
}

struct json_object *
ut_invoke(struct ut_state *state, uint32_t off, struct json_object *this,
          struct json_object *func, struct json_object *argvals)
{
	struct ut_op *op, *tag = json_object_get_userdata(func);
	struct ut_callstack callstack = {};
	struct ut_function *fn, *prev_fn;
	struct json_object *rv = NULL;
	struct ut_scope *sc;
	size_t arridx;
	ut_c_fn *cfn;

	if (!tag)
		return NULL;

	op = ut_get_op(state, off);

	callstack.next = state->callstack;
	callstack.source = state->source;
	callstack.funcname = state->function ? state->function->name : NULL;
	callstack.off = op ? op->off : 0;
	state->callstack = &callstack;

	/* is native function */
	if (tag->type == T_CFUNC) {
		cfn = (ut_c_fn *)tag->tag.data;
		rv = cfn ? cfn(state, off, argvals) : NULL;
	}

	/* is utpl function */
	else {
		fn = tag->tag.data;
		fn->scope = ut_new_scope(state, fn->parent_scope);
		fn->scope->ctx = json_object_get(this ? this : state->ctx);

		sc = state->scope;

		state->scope = ut_acquire_scope(fn->scope);

		prev_fn = state->function;
		state->function = fn;

		if (fn->args)
			for (arridx = 0; arridx < json_object_array_length(fn->args); arridx++)
				ut_setval(fn->scope->scope, json_object_array_get_idx(fn->args, arridx),
				          argvals ? json_object_array_get_idx(argvals, arridx) : NULL);

		rv = ut_execute_op_sequence(state, fn->entry);
		tag = json_object_get_userdata(rv);

		switch (tag ? tag->type : 0) {
		case T_BREAK:
		case T_CONTINUE:
			json_object_put(rv);
			rv = ut_new_exception(state, ut_get_off(state, tag),
			                      "Syntax error: %s statement must be inside loop",
			                      ut_get_tokenname(tag->type));
			break;

		case T_RETURN:
			json_object_put(rv);
			rv = json_object_get(state->rval);
			break;
		}

		/* we left the function, pop the function scope... */
		ut_release_scope(state->scope);
		state->scope = sc;

		/* ... and remove the "this" context... */
		json_object_put(fn->scope->ctx);
		fn->scope->ctx = NULL;

		/* ... and reset the function scope... */
		ut_release_scope(fn->scope);
		fn->scope = NULL;

		state->function = prev_fn;
	}

	state->callstack = callstack.next;

	return rv;
}

static struct json_object *
ut_execute_call(struct ut_state *state, uint32_t off)
{
	struct ut_op *decl, *op = ut_get_op(state, off);
	struct ut_op *op1 = ut_get_child(state, off, 0);
	struct json_object *v[2], *rv;
	char *lhs;

	ut_get_operands(state, op, v);

	decl = json_object_get_userdata(v[0]);

	if (!decl || (decl->type != T_FUNC && decl->type != T_CFUNC)) {
		lhs = ut_ref_to_str(state, ut_get_off(state, op1));

		rv = ut_new_exception(state, op1->off, "Type error: %s is not a function",
		                      lhs ? lhs : "left-hand side expression");

		free(lhs);
	}
	else {
		if (v[1] == NULL)
			v[1] = xjs_new_array();

		rv = ut_invoke(state, off, NULL, v[0], v[1]);
	}

	json_object_put(v[0]);
	json_object_put(v[1]);

	return rv;
}

static void
ut_write_str(struct json_object *v)
{
	const char *p;
	size_t len;

	switch (json_object_get_type(v)) {
	case json_type_object:
	case json_type_array:
		p = json_object_to_json_string_ext(v, JSON_C_TO_STRING_NOSLASHESCAPE|JSON_C_TO_STRING_SPACED);
		len = strlen(p);
		break;

	case json_type_string:
		p = json_object_get_string(v);
		len = json_object_get_string_len(v);
		break;

	case json_type_null:
		p = "";
		len = 0;
		break;

	default:
		p = json_object_get_string(v);
		len = strlen(p);
	}

	fwrite(p, 1, len, stdout);
}

static struct json_object *
ut_execute_exp(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *val = ut_execute_op_sequence(state, op ? op->tree.operand[0] : 0);
	struct ut_op *tag = val ? json_object_get_userdata(val) : NULL;

	switch (tag ? tag->type : 0) {
	case T_EXCEPTION:
		printf("<exception: %s>", json_object_get_string(val));
		break;

	default:
		ut_write_str(val);
		break;
	}

	json_object_put(val);

	return NULL;
}

static struct json_object *
ut_execute_unary_plus_minus(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct ut_op *op1 = ut_get_child(state, off, 0);
	struct json_object *v[1];
	enum json_type t;
	int64_t n;
	double d;

	ut_get_operands(state, op, v);

	t = ut_cast_number(v[0], &n, &d);

	json_object_put(v[0]);

	switch (t) {
	case json_type_int:
		if (op1->is_overflow)
			return xjs_new_int64(((n >= 0) == (op->type == T_SUB)) ? INT64_MIN : INT64_MAX);

		return xjs_new_int64((op->type == T_SUB) ? -n : n);

	default:
		return ut_new_double((op->type == T_SUB) ? -d : d);
	}
}

static struct json_object *
ut_execute_arith(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *v[2], *rv;
	enum json_type t1, t2;
	const char *s1, *s2;
	size_t len1, len2;
	int64_t n1, n2;
	double d1, d2;
	char *s;

	if (!op->tree.operand[1])
		return ut_execute_unary_plus_minus(state, off);

	ut_get_operands(state, op, v);

	if (op->type == T_ADD &&
	    (json_object_is_type(v[0], json_type_string) ||
	     json_object_is_type(v[1], json_type_string))) {
		s1 = v[0] ? json_object_get_string(v[0]) : "null";
		s2 = v[1] ? json_object_get_string(v[1]) : "null";
		len1 = strlen(s1);
		len2 = strlen(s2);
		s = xalloc(len1 + len2 + 1);

		snprintf(s, len1 + len2 + 1, "%s%s", s1, s2);

		rv = xjs_new_string(s);

		json_object_put(v[0]);
		json_object_put(v[1]);
		free(s);

		return rv;
	}

	t1 = ut_cast_number(v[0], &n1, &d1);
	t2 = ut_cast_number(v[1], &n2, &d2);

	json_object_put(v[0]);
	json_object_put(v[1]);

	if (t1 == json_type_double || t2 == json_type_double) {
		d1 = (t1 == json_type_double) ? d1 : (double)n1;
		d2 = (t2 == json_type_double) ? d2 : (double)n2;

		switch (op->type) {
		case T_ADD:
			return ut_new_double(d1 + d2);

		case T_SUB:
			return ut_new_double(d1 - d2);

		case T_MUL:
			return ut_new_double(d1 * d2);

		case T_DIV:
			if (d2 == 0.0)
				return ut_new_double(INFINITY);
			else if (isnan(d2))
				return ut_new_double(NAN);
			else if (!isfinite(d2))
				return ut_new_double(isfinite(d1) ? 0.0 : NAN);

			return ut_new_double(d1 / d2);

		case T_MOD:
			return ut_new_double(NAN);
		}
	}

	switch (op->type) {
	case T_ADD:
		return xjs_new_int64(n1 + n2);

	case T_SUB:
		return xjs_new_int64(n1 - n2);

	case T_MUL:
		return xjs_new_int64(n1 * n2);

	case T_DIV:
		if (n2 == 0)
			return ut_new_double(INFINITY);

		return xjs_new_int64(n1 / n2);

	case T_MOD:
		return xjs_new_int64(n1 % n2);
	}

	return ut_new_double(NAN);
}

static struct json_object *
ut_execute_bitop(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *v[2];
	int64_t n1, n2;
	double d;

	ut_get_operands(state, op, v);

	if (ut_cast_number(v[0], &n1, &d) == json_type_double)
		n1 = isnan(d) ? 0 : (int64_t)d;

	if (ut_cast_number(v[1], &n2, &d) == json_type_double)
		n2 = isnan(d) ? 0 : (int64_t)d;

	json_object_put(v[0]);
	json_object_put(v[1]);

	switch (op->type) {
	case T_LSHIFT:
		return xjs_new_int64(n1 << n2);

	case T_RSHIFT:
		return xjs_new_int64(n1 >> n2);

	case T_BAND:
		return xjs_new_int64(n1 & n2);

	case T_BXOR:
		return xjs_new_int64(n1 ^ n2);

	case T_BOR:
		return xjs_new_int64(n1 | n2);

	default:
		return NULL;
	}
}

static struct json_object *
ut_execute_not(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);

	return xjs_new_boolean(!ut_test_condition(state, op ? op->tree.operand[0] : 0));
}

static struct json_object *
ut_execute_compl(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *v[1];
	int64_t n;
	double d;

	ut_get_operands(state, op, v);

	if (ut_cast_number(v[0], &n, &d) == json_type_double)
		n = isnan(d) ? 0 : (int64_t)d;

	json_object_put(v[0]);

	return xjs_new_int64(~n);
}

static struct json_object *
ut_execute_return(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *v[1], *rv;

	ut_get_operands(state, op, v);

	json_object_put(state->rval);
	state->rval = v[0];

	rv = xjs_new_boolean(false);

	json_object_set_userdata(rv, op, NULL);

	return rv;
}

static struct json_object *
ut_execute_break_cont(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *rv = xjs_new_int64(0);

	json_object_set_userdata(rv, op, NULL);

	return rv;
}

static struct json_object *
ut_execute_function(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct ut_op *op1 = ut_get_child(state, off, 0);
	struct json_object *obj = ut_new_func(state, op, state->scope);

	if (op1)
		ut_setval(state->scope->scope, op1->val, obj);

	return obj;
}

static struct json_object *
ut_execute_this(struct ut_state *state, uint32_t off)
{
	return json_object_get(state->scope->ctx);
}

static struct json_object *
ut_execute_try_catch(struct ut_state *state, uint32_t off)
{
	struct ut_op *tag, *op = ut_get_op(state, off);
	struct json_object *rv;

	rv = ut_execute_op_sequence(state, op->tree.operand[0]);

	if (ut_is_type(rv, T_EXCEPTION)) {
		if (op->tree.operand[1]) {
			/* remove the T_EXCEPTION type from the object to avoid handling
			 * it as a new exception in the catch block */
			tag = json_object_get_userdata(rv);
			tag->type = T_LBRACE;

			json_object_put(ut_setval(state->scope->scope, ut_get_child(state, off, 1)->val,
			                json_object_get(rv)));
		}

		json_object_put(state->exception);
		state->exception = NULL;

		json_object_put(rv);
		rv = ut_execute_op_sequence(state, op->tree.operand[2]);
	}

	return rv;
}

static bool
ut_match_case(struct ut_state *state, struct json_object *v, struct ut_op *Case)
{
	struct json_object *caseval = ut_execute_op_sequence(state, Case->tree.operand[0]);
	bool rv = ut_eq(v, caseval);

	json_object_put(caseval);
	return rv;
}

static struct json_object *
ut_execute_switch_case(struct ut_state *state, uint32_t off)
{
	struct ut_op *Default = NULL, *Case = NULL, *jmp = NULL;
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *v[1], *rv = NULL;

	ut_get_operands(state, op, v);

	/* First try to find matching case... */
	for (Case = ut_get_child(state, off, 1);
	     Case != NULL;
	     Case = ut_get_op(state, Case->tree.next))
	{
		/* remember default case and throw on dupes */
		if (Case->type == T_DEFAULT) {
			if (Default) {
				json_object_put(v[0]);

				return ut_new_exception(state, Case->off,
				                        "Syntax error: more than one switch default case");
			}

			Default = Case;
			continue;
		}

		/* Found a matching case, remember jump offset */
		if (ut_match_case(state, v[0], Case)) {
			jmp = Case;
			break;
		}
	}

	/* jump to matching case (or default) and continue until break */
	for (Case = jmp ? jmp : Default;
	     Case != NULL;
	     Case = ut_get_op(state, Case->tree.next))
	{
		json_object_put(rv);

		if (Case == Default)
			rv = ut_execute_op_sequence(state, Default->tree.operand[0]);
		else
			rv = ut_execute_op_sequence(state, Case->tree.operand[1]);

		if (ut_is_type(rv, T_BREAK)) {
			json_object_put(rv);
			rv = NULL;
			break;
		}
		else if (ut_is_type(rv, T_RETURN) || ut_is_type(rv, T_EXCEPTION) || ut_is_type(rv, T_CONTINUE)) {
			break;
		}
	}

	json_object_put(v[0]);

	return rv;
}

static struct json_object *
ut_execute_atom(struct ut_state *state, uint32_t off)
{
	return json_object_get(ut_get_op(state, off)->val);
}

static struct json_object *
ut_execute_text(struct ut_state *state, uint32_t off)
{
	printf("%s", json_object_get_string(ut_get_op(state, off)->val));

	return NULL;
}

static struct json_object *
ut_execute_label(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *scope, *key, *val;

	scope = ut_getref(state, off, &key);

	json_object_put(state->ctx);
	state->ctx = NULL;

	if (state->strict_declarations && scope == NULL) {
		return ut_new_exception(state, op->off,
		                        "Reference error: %s is not defined",
		                        json_object_get_string(op->val));
	}

	val = ut_getval(scope, key);
	json_object_put(scope);
	json_object_put(key);

	return val;
}

static struct json_object *
ut_execute_dot(struct ut_state *state, uint32_t off)
{
	struct json_object *scope, *key, *val;

	scope = ut_getref_required(state, off, &key);

	json_object_put(state->ctx);
	state->ctx = json_object_get(scope);

	if (!key)
		return scope;

	val = ut_getval(scope, key);
	json_object_put(scope);
	json_object_put(key);

	return val;
}

static struct json_object *
ut_execute_lbrack(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);

	/* postfix access */
	if (op->is_postfix)
		return ut_execute_dot(state, off);

	return ut_execute_list(state, op->tree.operand[0]);
}

static struct json_object *(*fns[__T_MAX])(struct ut_state *, uint32_t) = {
	[T_NUMBER]   = ut_execute_atom,
	[T_DOUBLE]   = ut_execute_atom,
	[T_STRING]   = ut_execute_atom,
	[T_REGEXP]   = ut_execute_atom,
	[T_BOOL]     = ut_execute_atom,
	[T_NULL]     = ut_execute_atom,
	[T_THIS]     = ut_execute_this,
	[T_FUNC]     = ut_execute_function,
	[T_TEXT]     = ut_execute_text,
	[T_ASSIGN]   = ut_execute_assign,
	[T_LOCAL]    = ut_execute_local,
	[T_LABEL]    = ut_execute_label,
	[T_DOT]      = ut_execute_dot,
	[T_LBRACK]   = ut_execute_lbrack,
	[T_LBRACE]   = ut_execute_object,
	[T_IF]       = ut_execute_if,
	[T_QMARK]    = ut_execute_if,
	[T_FOR]      = ut_execute_for,
	[T_WHILE]    = ut_execute_while,
	[T_AND]      = ut_execute_and_or,
	[T_OR]       = ut_execute_and_or,
	[T_LT]       = ut_execute_rel,
	[T_LE]       = ut_execute_rel,
	[T_GT]       = ut_execute_rel,
	[T_GE]       = ut_execute_rel,
	[T_EQ]       = ut_execute_rel,
	[T_NE]       = ut_execute_rel,
	[T_EQS]      = ut_execute_equality,
	[T_NES]      = ut_execute_equality,
	[T_IN]       = ut_execute_in,
	[T_INC]      = ut_execute_inc_dec,
	[T_DEC]      = ut_execute_inc_dec,
	[T_LPAREN]   = ut_execute_call,
	[T_LEXP]     = ut_execute_exp,
	[T_ADD]      = ut_execute_arith,
	[T_SUB]      = ut_execute_arith,
	[T_MUL]      = ut_execute_arith,
	[T_DIV]      = ut_execute_arith,
	[T_MOD]      = ut_execute_arith,
	[T_LSHIFT]   = ut_execute_bitop,
	[T_RSHIFT]   = ut_execute_bitop,
	[T_BAND]     = ut_execute_bitop,
	[T_BXOR]     = ut_execute_bitop,
	[T_BOR]      = ut_execute_bitop,
	[T_COMPL]    = ut_execute_compl,
	[T_NOT]      = ut_execute_not,
	[T_RETURN]   = ut_execute_return,
	[T_BREAK]    = ut_execute_break_cont,
	[T_CONTINUE] = ut_execute_break_cont,
	[T_TRY]      = ut_execute_try_catch,
	[T_SWITCH]   = ut_execute_switch_case,
};

static struct json_object *
ut_execute_op(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);

	if (!fns[op->type])
		return ut_new_exception(state, op->off, "Runtime error: Unrecognized opcode %d", op->type);

	return fns[op->type](state, off);
}

static struct json_object *
ut_execute_op_sequence(struct ut_state *state, uint32_t off)
{
	struct json_object *v = NULL;
	struct ut_op *tag = NULL;
	struct ut_op *op = NULL;

	while (off) {
		json_object_put(v);

		v = ut_execute_op(state, off);
		tag = v ? json_object_get_userdata(v) : NULL;

		switch (tag ? tag->type : 0) {
		case T_BREAK:
		case T_CONTINUE:
		case T_RETURN:
		case T_EXCEPTION:
			return v;
		}

		op = ut_get_op(state, off);
		off = op ? op->tree.next : 0;
	}

	return v;
}

static void
ut_globals_init(struct ut_state *state, struct json_object *scope)
{
	struct json_object *arr = xjs_new_array();
	const char *p, *last;

	for (p = last = LIB_SEARCH_PATH;; p++) {
		if (*p == ':' || *p == '\0') {
			json_object_array_add(arr, xjs_new_string_len(last, p - last));

			if (!*p)
				break;

			last = p + 1;
		}
	}

	json_object_object_add(scope, "REQUIRE_SEARCH_PATH", arr);
}

static void
ut_register_variable(struct json_object *scope, const char *key, struct json_object *val)
{
	char *name = strdup(key);
	char *p;

	if (!name)
		return;

	for (p = name; *p; p++)
		if (!isalnum(*p) && *p != '_')
			*p = '_';

	json_object_object_add(scope, name, val);
	free(name);
}

struct json_object *
ut_run(struct ut_state *state, struct json_object *env, struct json_object *modules)
{
	struct json_object *args, *rv;
	size_t i;

	state->scope = ut_new_scope(state, NULL);
	state->ctx = NULL;

	if (env) {
		json_object_object_foreach(env, key, val)
			ut_register_variable(state->scope->scope, key, json_object_get(val));
	}

	ut_globals_init(state, state->scope->scope);
	ut_lib_init(state, state->scope->scope);

	if (modules) {
		args = xjs_new_array();

		for (i = 0; i < json_object_array_length(modules); i++) {
			json_object_array_put_idx(args, 0, json_object_get(json_object_array_get_idx(modules, i)));

			rv = ut_invoke(state, 0, NULL,
			               json_object_object_get(state->scope->scope, "require"),
			               args);

			if (ut_is_type(rv, T_EXCEPTION))
				goto out;

			ut_register_variable(state->scope->scope,
			                     json_object_get_string(json_object_array_get_idx(modules, i)),
			                     rv);
		}

		json_object_put(args);
	}

	rv = ut_execute_source(state, state->source, state->scope);

out:
	ut_release_scope(state->scope);

	return rv;
}
