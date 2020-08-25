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


static struct ut_opcode exception_tag = { .type = T_EXCEPTION };

__attribute__((format(printf, 3, 0))) struct json_object *
ut_exception(struct ut_state *state, struct ut_opcode *op, const char *fmt, ...)
{
	struct json_object *msg;
	va_list ap;
	char *s;
	int len;

	va_start(ap, fmt);
	len = vasprintf(&s, fmt, ap);
	va_end(ap);

	if (len < 0) {
		msg = json_object_new_string(UT_ERRMSG_OOM);
	}
	else {
		msg = json_object_new_string_len(s, len);
		free(s);
	}

	exception_tag.operand[0] = op;

	json_object_set_userdata(msg, &exception_tag, NULL);

	state->error.code = UT_ERROR_EXCEPTION;
	state->error.info.exception = msg;

	return json_object_get(msg);
}

bool
ut_val_is_truish(struct json_object *val)
{
	double d;

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
ut_getscope(struct ut_state *state, uint8_t depth)
{
	if (depth >= state->stack.off)
		return NULL;

	return state->stack.scope[state->stack.off - depth - 1];
}

static struct json_object *
ut_addscope(struct ut_state *state, struct ut_opcode *decl)
{
	struct json_object *scope, **tmp;

	if (state->stack.off >= 255)
		return ut_exception(state, decl, "Runtime error: Too much recursion");

	if (state->stack.off >= state->stack.size) {
		tmp = realloc(state->stack.scope, (state->stack.size + 1) * sizeof(*state->stack.scope));

		if (!tmp)
			return ut_exception(state, decl, UT_ERRMSG_OOM);

		state->stack.scope = tmp;
		state->stack.size++;
	}

	scope = json_object_new_object();

	if (!scope)
		return ut_exception(state, decl, UT_ERRMSG_OOM);

	state->stack.scope[state->stack.off++] = scope;

	return scope;
}

void
ut_putval(struct json_object *val)
{
	struct ut_opcode *tag = json_object_get_userdata(val);

	if (tag && tag->val != val)
		json_object_put(tag->val);

	json_object_put(val);
}

static struct json_object *
ut_execute_op(struct ut_state *state, struct ut_opcode *op);

static char *
ut_ref_to_str(struct ut_opcode *op)
{
	struct ut_opcode *op1 = op->operand[0];
	struct ut_opcode *op2 = op->operand[1];
	const char *l;
	size_t n1, n2;
	char *s, *p;

	switch (op ? op->type : 0) {
	case T_DOT:
		s = ut_ref_to_str(op1);
		n1 = strlen(s ? s : "(null)");

		l = ((op2 ? op2->type : 0) == T_LABEL) ? json_object_get_string(op2->val) : "???";
		n2 = strlen(l);

		p = calloc(1, n1 + n2 + 2);

		if (!p)
			return NULL;

		snprintf(p, n1 + n2 + 2, "%s.%s", s ? s : "(null)", l);
		free(s);

		return p;

	case T_LBRACK:
		if (!op->val)
			return NULL;

		s = ut_ref_to_str(op1);
		n1 = strlen(s ? s : "(null)");

		l = "...";
		n2 = strlen(l);

		p = calloc(1, n1 + n2 + 3);

		if (!p)
			return NULL;

		snprintf(p, n1 + n2 + 3, "%s[%s]", s, l);
		free(s);

		return p;

	case T_LABEL:
		return strdup(json_object_get_string(op->val));

	default:
		return NULL;
	}
}

static struct json_object *
ut_getref(struct ut_state *state, struct ut_opcode *op, struct json_object **key)
{
	struct json_object *scope, *next;
	uint8_t i;

	if (op && op->type == T_DOT) {
		*key = op->operand[1] ? op->operand[1]->val : NULL;

		return ut_execute_op(state, op->operand[0]);
	}
	else if (op && op->type == T_LBRACK && op->val) {
		*key = op->operand[1] ? ut_execute_op(state, op->operand[1]) : NULL;

		return ut_execute_op(state, op->operand[0]);
	}
	else if (op && op->type == T_LABEL) {
		i = 0;
		scope = ut_getscope(state, i);

		while (true) {
			if (json_object_object_get_ex(scope, json_object_get_string(op->val), NULL))
				break;

			next = ut_getscope(state, ++i);

			if (!next)
				break;

			scope = next;
		}

		*key = op->val;

		return scope;
	}
	else {
		*key = NULL;

		return NULL;
	}
}

static struct json_object *
ut_getref_required(struct ut_state *state, struct ut_opcode *op, struct json_object **key)
{
	struct json_object *scope, *skey, *rv;
	char *lhs;

	scope = ut_getref(state, op, &skey);

	if (!json_object_is_type(scope, json_type_array) &&
		!json_object_is_type(scope, json_type_object)) {
		lhs = ut_ref_to_str(op->operand[0]);

		if (lhs) {
			rv = ut_exception(state, op->operand[0], "Type error: %s is null", lhs);

			free(lhs);
		}
		else {
			rv = ut_exception(state, op->operand[0],
				"Syntax error: Invalid left-hand side operand %s for %s",
				tokennames[op->operand[0]->type], tokennames[op->type]);
		}

		*key = NULL;
		return rv;
	}

	*key = skey;
	return scope;
}

static struct json_object *
ut_getval(struct json_object *scope, struct json_object *key)
{
	int64_t idx;
	double d;

	if (!key)
		return NULL;

	if (json_object_is_type(scope, json_type_array)) {
		/* only consider doubles with integer values as array keys */
		if (json_object_is_type(key, json_type_double)) {
			d = json_object_get_double(key);

			if (ceil(d) != d)
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

	return json_object_get(json_object_object_get(scope, key ? json_object_get_string(key) : "null"));
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
ut_execute_assign(struct ut_state *state, struct ut_opcode *op)
{
	struct ut_opcode *label = op->operand[0];
	struct ut_opcode *value = op->operand[1];
	struct json_object *scope, *key;

	scope = ut_getref_required(state, label, &key);

	return key ? ut_setval(scope, key, ut_execute_op(state, value)) : scope;
}

static struct json_object *
ut_execute_local(struct ut_state *state, struct ut_opcode *op)
{
	struct ut_opcode *as = op->operand[0];
	struct json_object *rv = NULL;

	while (as) {
		rv = ut_setval(
			state->stack.scope[state->stack.off-1], as->operand[0]->val,
			as->operand[1] ? ut_execute_op(state, as->operand[1]) : NULL);

		as = as->sibling;
	}

	return rv;
}

static struct json_object *
ut_execute_op_sequence(struct ut_state *state, struct ut_opcode *op);

static bool
ut_test_condition(struct ut_state *state, struct ut_opcode *op)
{
	struct json_object *val = ut_execute_op_sequence(state, op);
	bool istrue = ut_val_is_truish(val);

	ut_putval(val);

	return istrue;
}

static struct json_object *
ut_execute_if(struct ut_state *state, struct ut_opcode *op)
{
	struct ut_opcode *cond = op->operand[0];
	struct ut_opcode *Then = op->operand[1];
	struct ut_opcode *Else = op->operand[2];

	if (ut_test_condition(state, cond))
		return ut_execute_op_sequence(state, Then);
	else if (Else)
		return ut_execute_op_sequence(state, Else);

	return NULL;
}

static struct json_object *
ut_execute_for(struct ut_state *state, struct ut_opcode *op)
{
	struct json_object *ivar, *val, *item, *rv = NULL;
	struct ut_opcode *init = op->operand[0];
	struct ut_opcode *test = op->operand[1];
	struct ut_opcode *incr = op->operand[2];
	struct ut_opcode *body = op->operand[3];
	struct ut_opcode *tag;
	size_t arridx, arrlen;

	/* for (x in ...) loop variant */
	if (init != NULL && test == NULL && incr == NULL) {
		if (init->type != T_IN)
			return ut_exception(state, init, "Syntax error: missing ';' after for loop initializer");

		ivar = init->operand[0]->val;
		val = ut_execute_op(state, init->operand[1]);

		if (json_object_is_type(val, json_type_array)) {
			for (arridx = 0, arrlen = json_object_array_length(val);
			     arridx < arrlen; arridx++) {
				item = json_object_array_get_idx(val, arridx);

				ut_setval(ut_getscope(state, 0), ivar, item);
				ut_putval(rv);

				rv = ut_execute_op_sequence(state, body);
				tag = json_object_get_userdata(rv);

				switch (tag ? tag->type : 0) {
				case T_RETURN:
				case T_EXCEPTION:
					ut_putval(val);

					return rv;

				case T_BREAK:
					ut_putval(val);
					ut_putval(rv);

					return NULL;
				}
			}
		}
		else if (json_object_is_type(val, json_type_object)) {
			json_object_object_foreach(val, key, item) {
				ut_setval(ut_getscope(state, 0), ivar, json_object_new_string(key));
				ut_putval(rv);

				rv = ut_execute_op_sequence(state, body);
				tag = json_object_get_userdata(rv);

				switch (tag ? tag->type : 0) {
				case T_RETURN:
				case T_EXCEPTION:
					ut_putval(val);

					return rv;

				case T_BREAK:
					ut_putval(val);
					ut_putval(rv);

					return NULL;
				}
			}
		}

		ut_putval(val);
		ut_putval(rv);

		return NULL;
	}

	if (init)
		ut_putval(ut_execute_op_sequence(state, init));

	while (test ? ut_test_condition(state, test) : true) {
		ut_putval(rv);

		rv = ut_execute_op_sequence(state, body);
		tag = json_object_get_userdata(rv);

		switch (tag ? tag->type : 0) {
		case T_RETURN:
		case T_EXCEPTION:
			return rv;

		case T_BREAK:
			ut_putval(rv);

			return NULL;
		}

		if (incr)
			ut_putval(ut_execute_op_sequence(state, incr));
	}

	ut_putval(rv);

	return NULL;
}

static struct json_object *
ut_execute_while(struct ut_state *state, struct ut_opcode *op)
{
	struct ut_opcode *test = op->operand[0];
	struct ut_opcode *body = op->operand[1];
	struct json_object *v, *rv = NULL;
	struct ut_opcode *tag = NULL;
	bool cond;

	while (1) {
		v = test ? ut_execute_op_sequence(state, test) : NULL;
		cond = test ? ut_val_is_truish(v) : true;

		ut_putval(rv);
		ut_putval(v);

		if (!cond)
			return NULL;

		rv = ut_execute_op_sequence(state, body);
		tag = json_object_get_userdata(rv);

		switch (tag ? tag->type : 0) {
		case T_RETURN:
		case T_EXCEPTION:
			return rv;

		case T_BREAK:
			ut_putval(rv);

			return NULL;
		}
	}

	ut_putval(rv);

	return NULL;
}

static struct json_object *
ut_execute_and_or(struct ut_state *state, struct ut_opcode *op)
{
	struct json_object *val = NULL;
	int i;

	for (i = 0; i < sizeof(op->operand) / sizeof(op->operand[0]); i++) {
		if (!op->operand[i])
			break;

		ut_putval(val);

		val = ut_execute_op(state, op->operand[i]);

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
ut_execute_rel(struct ut_state *state, struct ut_opcode *op)
{
	struct json_object *v1 = ut_execute_op(state, op->operand[0]);
	struct json_object *v2 = ut_execute_op(state, op->operand[1]);
	struct json_object *rv;

	rv = json_object_new_boolean(ut_cmp(op->type, v1, v2));

	ut_putval(v1);
	ut_putval(v2);

	return rv;
}

static struct json_object *
ut_execute_in(struct ut_state *state, struct ut_opcode *op)
{
	struct json_object *op1 = ut_execute_op(state, op->operand[0]);
	struct json_object *op2 = ut_execute_op(state, op->operand[1]);
	struct json_object *item;
	size_t arrlen, arridx;
	bool found = false;
	const char *key;

	if (json_object_is_type(op2, json_type_array)) {
		for (arridx = 0, arrlen = json_object_array_length(op2);
		     arridx < arrlen; arridx++) {
			item = json_object_array_get_idx(op2, arridx);

			if (ut_cmp(T_EQ, op1, item)) {
				found = true;
				break;
			}
		}
	}
	else if (json_object_is_type(op2, json_type_object)) {
		key = op1 ? json_object_get_string(op1) : "null";
		found = json_object_object_get_ex(op2, key, NULL);
	}

	ut_putval(op1);
	ut_putval(op2);

	return json_object_new_boolean(found);
}

static struct json_object *
ut_execute_inc_dec(struct ut_state *state, struct ut_opcode *op)
{
	struct json_object *val, *nval, *scope, *key;
	struct ut_opcode *label = op->operand[0];
	int64_t n;
	double d;

	scope = ut_getref_required(state, label, &key);

	if (!key)
		return scope;

	val = ut_getval(scope, key);

	if (ut_cast_number(val, &n, &d) == json_type_double)
		nval = json_object_new_double_rounded(d + (op->type == T_INC ? 1.0 : -1.0));
	else
		nval = json_object_new_int64(n + (op->type == T_INC ? 1 : -1));

	ut_putval(ut_setval(scope, key, nval));

	/* postfix inc/dec, return old val */
	if (op->val)
		return val;

	ut_putval(val);

	return json_object_get(nval);
}

static struct json_object *
ut_execute_list(struct ut_state *state, struct ut_opcode *op)
{
	struct json_object *arr = json_object_new_array();

	if (!arr)
		return ut_exception(state, op, UT_ERRMSG_OOM);

	while (op) {
		json_object_array_add(arr, ut_execute_op(state, op));
		op = op->sibling;
	}

	return arr;
}

static struct json_object *
ut_execute_object(struct ut_state *state, struct ut_opcode *op)
{
	struct json_object *obj = json_object_new_object();
	struct ut_opcode *key, *val;

	if (!obj)
		return ut_exception(state, op, UT_ERRMSG_OOM);

	for (key = op->operand[0], val = key ? key->sibling : NULL;
	     key != NULL && val != NULL;
	     key = val->sibling, val = key ? key->sibling : NULL) {
		json_object_object_add(obj, json_object_get_string(key->val),
			ut_execute_op(state, val));
	}

	return obj;
}

struct json_object *
ut_invoke(struct ut_state *state, struct ut_opcode *op, struct json_object *scope,
          struct json_object *func, struct json_object *argvals)
{
	struct ut_opcode *decl = json_object_get_userdata(func);
	struct ut_opcode *arg = decl ? decl->operand[1] : NULL;
	struct json_object *s, *rv = NULL;
	struct ut_opcode *tag;
	size_t arridx;
	ut_c_fn *cfn;

	if (!decl)
		return NULL;

	/* is native function */
	if (decl->type == T_CFUNC) {
		cfn = (ut_c_fn *)decl->operand[0];

		return cfn ? cfn(state, op, argvals) : NULL;
	}

	s = scope ? scope : ut_addscope(state, decl);

	if (!json_object_is_type(s, json_type_object))
		return s;

	for (arridx = 0; arg; arridx++, arg = arg->sibling)
		ut_setval(s, arg->val, argvals ? json_object_array_get_idx(argvals, arridx) : NULL);

	json_object_set_userdata(s, json_object_get(state->ctx), NULL);

	rv = ut_execute_op_sequence(state, decl->operand[2]);
	tag = json_object_get_userdata(rv);

	switch (tag ? tag->type : 0) {
	case T_BREAK:
	case T_CONTINUE:
		ut_putval(rv);
		rv = ut_exception(state, tag, "Syntax error: %s statement must be inside loop",
		                  tokennames[tag->type]);
		break;

	case T_RETURN:
		/* handle magic null */
		if (json_object_is_type(rv, json_type_boolean)) {
			if (!strcmp(json_object_get_string(rv), "null")) {
				ut_putval(rv);
				rv = NULL;
			}
		}

		break;
	}

	if (!scope) {
		state->stack.scope[--state->stack.off] = NULL;

		json_object_put(json_object_get_userdata(s));
		json_object_put(s);
	}

	return rv;
}

static struct json_object *
ut_execute_call(struct ut_state *state, struct ut_opcode *op)
{
	struct json_object *func = ut_execute_op(state, op->operand[0]);
	struct ut_opcode *decl = func ? json_object_get_userdata(func) : NULL;
	struct json_object *argvals = ut_execute_list(state, op->operand[1]);
	struct json_object *rv;
	char *lhs;

	if (!decl || (decl->type != T_FUNC && decl->type != T_CFUNC)) {
		lhs = ut_ref_to_str(op->operand[0]);
		rv = ut_exception(state, op->operand[0],
			"Type error: %s is not a function",
			lhs ? lhs : "left-hand side expression");

		free(lhs);
	}
	else {
		rv = ut_invoke(state, op, NULL, func, argvals);
	}

	ut_putval(argvals);
	ut_putval(func);

	return rv;
}

static void
ut_write_str(struct json_object *v)
{
	const char *p;
	size_t len;

	p = v ? json_object_get_string(v) : "";
	len = json_object_is_type(v, json_type_string) ? json_object_get_string_len(v) : strlen(p);

	fwrite(p, 1, len, stdout);
}

static struct json_object *
ut_execute_exp(struct ut_state *state, struct ut_opcode *op)
{
	struct json_object *val = ut_execute_op_sequence(state, op->operand[0]);
	struct ut_opcode *tag = val ? json_object_get_userdata(val) : NULL;

	switch (tag ? tag->type : 0) {
	case T_RETURN:
		ut_write_str(tag->val);
		break;

	case T_BREAK:
		return val;

	case T_EXCEPTION:
		printf("<exception: %s>", json_object_get_string(val));
		break;

	default:
		ut_write_str(val);
		break;
	}

	ut_putval(val);

	return NULL;
}

static struct json_object *
ut_execute_unary_plus_minus(struct ut_state *state, struct ut_opcode *op)
{
	struct json_object *val = ut_execute_op(state, op->operand[0]);
	enum json_type t;
	int64_t n;
	double d;

	t = ut_cast_number(val, &n, &d);

	ut_putval(val);

	switch (t) {
	case json_type_int:
		return json_object_new_int64((op->type == T_SUB) ? -n : n);

	default:
		return json_object_new_double_rounded((op->type == T_SUB) ? -d : d);
	}
}

static struct json_object *
ut_execute_arith(struct ut_state *state, struct ut_opcode *op)
{
	struct json_object *v1, *v2, *rv;
	enum json_type t1, t2;
	const char *s1, *s2;
	size_t len1, len2;
	int64_t n1, n2;
	double d1, d2;
	char *s;

	if (!op->operand[1])
		return ut_execute_unary_plus_minus(state, op);

	v1 = ut_execute_op(state, op->operand[0]);
	v2 = ut_execute_op(state, op->operand[1]);

	if (op->type == T_ADD &&
	    (json_object_is_type(v1, json_type_string) ||
	     json_object_is_type(v2, json_type_string))) {
		s1 = v1 ? json_object_get_string(v1) : "null";
		s2 = v1 ? json_object_get_string(v2) : "null";
		len1 = strlen(s1);
		len2 = strlen(s2);
		s = calloc(1, len1 + len2 + 1);

		if (!s) {
			ut_putval(v1);
			ut_putval(v2);

			return NULL;
		}

		snprintf(s, len1 + len2 + 1, "%s%s", s1, s2);

		rv = json_object_new_string(s);

		ut_putval(v1);
		ut_putval(v2);
		free(s);

		return rv;
	}

	t1 = ut_cast_number(v1, &n1, &d1);
	t2 = ut_cast_number(v2, &n2, &d2);

	ut_putval(v1);
	ut_putval(v2);

	if (t1 == json_type_double || t2 == json_type_double) {
		d1 = (t1 == json_type_double) ? d1 : (double)n1;
		d2 = (t2 == json_type_double) ? d2 : (double)n2;

		switch (op->type) {
		case T_ADD:
			return json_object_new_double_rounded(d1 + d2);

		case T_SUB:
			return json_object_new_double_rounded(d1 - d2);

		case T_MUL:
			return json_object_new_double_rounded(d1 * d2);

		case T_DIV:
			if (d2 == 0.0)
				return json_object_new_double_rounded(NAN);

			return json_object_new_double_rounded(d1 / d2);

		case T_MOD:
			return json_object_new_double_rounded(NAN);
		}
	}

	switch (op->type) {
	case T_ADD:
		return json_object_new_int64(n1 + n2);

	case T_SUB:
		return json_object_new_int64(n1 - n2);

	case T_MUL:
		return json_object_new_int64(n1 * n2);

	case T_DIV:
		if (n2 == 0)
			return json_object_new_double_rounded(NAN);

		return json_object_new_int64(n1 / n2);

	case T_MOD:
		return json_object_new_int64(n1 % n2);
	}

	return json_object_new_double_rounded(NAN);
}

static struct json_object *
ut_execute_bitop(struct ut_state *state, struct ut_opcode *op)
{
	struct ut_opcode *op1 = op->operand[0];
	struct ut_opcode *op2 = op->operand[1];
	struct json_object *v1, *v2;
	int64_t n1, n2;
	double d;

	v1 = op1 ? ut_execute_op(state, op1) : NULL;
	v2 = op2 ? ut_execute_op(state, op2) : NULL;

	if (ut_cast_number(v1, &n1, &d) == json_type_double)
		n1 = isnan(d) ? 0 : (int64_t)d;

	if (ut_cast_number(v2, &n2, &d) == json_type_double)
		n2 = isnan(d) ? 0 : (int64_t)d;

	ut_putval(v1);
	ut_putval(v2);

	switch (op->type) {
	case T_LSHIFT:
		return json_object_new_int64(n1 << n2);

	case T_RSHIFT:
		return json_object_new_int64(n1 >> n2);

	case T_BAND:
		return json_object_new_int64(n1 & n2);

	case T_BXOR:
		return json_object_new_int64(n1 ^ n2);

	case T_BOR:
		return json_object_new_int64(n1 | n2);

	default:
		return NULL;
	}
}

static struct json_object *
ut_execute_not(struct ut_state *state, struct ut_opcode *op)
{
	return json_object_new_boolean(!ut_test_condition(state, op->operand[0]));
}

static struct json_object *
ut_execute_compl(struct ut_state *state, struct ut_opcode *op)
{
	struct json_object *val = op->operand[0] ? ut_execute_op(state, op->operand[0]) : NULL;
	int64_t n;
	double d;

	if (ut_cast_number(val, &n, &d) == json_type_double)
		n = isnan(d) ? 0 : (int64_t)d;

	ut_putval(val);

	return json_object_new_int64(~n);
}

static struct json_object *
ut_execute_return(struct ut_state *state, struct ut_opcode *op)
{
	struct json_object *val = op->operand[0] ? ut_execute_op(state, op->operand[0]) : NULL;

	if (!val)
		val = json_object_new_null_obj();

	json_object_set_userdata(val, op, NULL);

	return val;
}

static struct json_object *
ut_execute_break_cont(struct ut_state *state, struct ut_opcode *op)
{
	struct json_object *rv = json_object_new_int64(0);

	json_object_set_userdata(rv, op, NULL);

	return rv;
}

static struct json_object *
ut_execute_op(struct ut_state *state, struct ut_opcode *op)
{
	struct json_object *scope, *key;

	switch (op->type) {
	case T_NUMBER:
	case T_DOUBLE:
	case T_BOOL:
	case T_STRING:
		return json_object_get(op->val);

	case T_THIS:
		return json_object_get_userdata(ut_getscope(state, 0));

	case T_FUNC:
		if (op->operand[0])
			ut_setval(ut_getscope(state, 0), op->operand[0]->val, op->val);

		return json_object_get(op->val);

	case T_TEXT:
		printf("%s", json_object_get_string(op->val));

		return NULL;

	case T_ASSIGN:
		return ut_execute_assign(state, op);

	case T_LOCAL:
		return ut_execute_local(state, op);

	case T_LABEL:
		scope = ut_getref(state, op, &key);
		state->ctx = scope;

		return ut_getval(scope, key);

	case T_DOT:
		scope = ut_getref_required(state, op, &key);
		state->ctx = scope;

		return key ? ut_getval(scope, key) : scope;

	case T_LBRACK:
		/* postfix access */
		if (op->val) {
			scope = ut_getref_required(state, op, &key);
			state->ctx = scope;

			return key ? ut_getval(scope, key) : scope;
		}

		return ut_execute_list(state, op->operand[0]);

	case T_LBRACE:
		return ut_execute_object(state, op);

	case T_IF:
	case T_QMARK:
		return ut_execute_if(state, op);

	case T_FOR:
		return ut_execute_for(state, op);

	case T_WHILE:
		return ut_execute_while(state, op);

	case T_AND:
	case T_OR:
		return ut_execute_and_or(state, op);

	case T_LT:
	case T_LE:
	case T_GT:
	case T_GE:
	case T_EQ:
	case T_NE:
		return ut_execute_rel(state, op);

	case T_IN:
		return ut_execute_in(state, op);

	case T_INC:
	case T_DEC:
		return ut_execute_inc_dec(state, op);

	case T_LPAREN:
		return ut_execute_call(state, op);

	case T_LEXP:
		return ut_execute_exp(state, op);

	case T_ADD:
	case T_SUB:
	case T_MUL:
	case T_DIV:
	case T_MOD:
		return ut_execute_arith(state, op);

	case T_LSHIFT:
	case T_RSHIFT:
	case T_BAND:
	case T_BXOR:
	case T_BOR:
		return ut_execute_bitop(state, op);

	case T_COMPL:
		return ut_execute_compl(state, op);

	case T_NOT:
		return ut_execute_not(state, op);

	case T_RETURN:
		return ut_execute_return(state, op);

	case T_BREAK:
	case T_CONTINUE:
		return ut_execute_break_cont(state, op);

	default:
		return ut_exception(state, op, "Runtime error: Unrecognized opcode %d", op->type);
	}
}

static struct json_object *
ut_execute_op_sequence(struct ut_state *state, struct ut_opcode *op)
{
	struct json_object *v = NULL;
	struct ut_opcode *tag = NULL;

	while (op) {
		ut_putval(v);

		v = ut_execute_op(state, op);
		tag = v ? json_object_get_userdata(v) : NULL;

		switch (tag ? tag->type : 0) {
		case T_BREAK:
		case T_CONTINUE:
		case T_RETURN:
		case T_EXCEPTION:
			return v;
		}

		op = op->sibling;
	}

	return v;
}

enum ut_error_type
ut_run(struct ut_state *state)
{
	struct json_object *scope, *args, *rv;

	if (!state->main || state->main->type != T_FUNC || !state->main->val) {
		ut_exception(state, state->main, "Runtime error: Invalid root operation in AST");

		return UT_ERROR_EXCEPTION;
	}

	scope = ut_addscope(state, state->main);

	if (!json_object_is_type(scope, json_type_object))
		return UT_ERROR_EXCEPTION;

	state->ctx = scope;

	ut_lib_init(state, scope);

	args = json_object_new_array();
	rv = ut_invoke(state, state->main, NULL, state->main->val, args);

	json_object_put(args);
	json_object_put(rv);

	return state->error.code;
}
